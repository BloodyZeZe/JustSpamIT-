import requests
import time
import random
import concurrent.futures
import json
import sys
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Union, Optional
import threading
import re

# Configuración
BASE_URL = "https://discord.com/api/v9"
VERSION = "1.0"
DEFAULT_MAX_WORKERS = 10
MIN_DELAY = 0.5
MAX_DELAY = 2.0
BATCH_SIZE = 5
MAX_RETRIES = 3
CONFIG_FILE = "spammer_config.json"

# Configuración de logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("discord_spammer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DiscordSpammer")

class RateLimitHandler:
    """Gestiona los rate limits de Discord con estrategia de backoff exponencial"""
    def __init__(self):
        self.rate_limits = {}
        self.lock = threading.Lock()
    
    def should_wait(self, endpoint: str) -> float:
        """Comprueba si debemos esperar para este endpoint"""
        with self.lock:
            if endpoint in self.rate_limits:
                wait_until = self.rate_limits[endpoint]
                now = time.time()
                if now < wait_until:
                    return wait_until - now
            return 0
    
    def update_rate_limit(self, endpoint: str, retry_after: float, multiplier: float = 1.5):
        """Actualiza el rate limit con backoff exponencial"""
        with self.lock:
            wait_time = retry_after * multiplier
            self.rate_limits[endpoint] = time.time() + wait_time
            return wait_time

class DiscordClient:
    """Cliente de Discord con medidas anti-detección"""
    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        self.headers = self._get_headers()
        self.user_data = None
        self.rate_handler = RateLimitHandler()
    
    def _get_headers(self) -> Dict[str, str]:
        """Genera headers realistas para evitar detección"""
        return {
            "Authorization": self.token,
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVzLUVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzExOC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTE4LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjIyNDc1MCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=",
            "Accept-Language": "es-ES,es;q=0.9",
            "Accept": "*/*",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/channels/@me",
            # Añadir fingerprinting adicional
            "sec-ch-ua": '"Chromium";v="118", "Google Chrome";v="118"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin"
        }
    
    def request(self, method: str, endpoint: str, data: Optional[Dict] = None, retry_count: int = 0) -> Dict:
        """Realiza una petición a la API con manejo de rate limits y errores"""
        url = f"{BASE_URL}{endpoint}"
        endpoint_key = f"{method}:{endpoint}"
        
        # Comprobar si debemos esperar por rate limit
        wait_time = self.rate_handler.should_wait(endpoint_key)
        if wait_time > 0:
            time.sleep(wait_time)
        
        try:
            if method.upper() == "GET":
                response = self.session.get(url, headers=self.headers)
            elif method.upper() == "POST":
                response = self.session.post(url, headers=self.headers, json=data)
            else:
                raise ValueError(f"Método no soportado: {method}")
            
            # Manejar rate limits
            if response.status_code == 429:
                retry_after = response.json().get("retry_after", 1)
                wait_time = self.rate_handler.update_rate_limit(endpoint_key, retry_after)
                
                if retry_count < MAX_RETRIES:
                    time.sleep(wait_time)
                    return self.request(method, endpoint, data, retry_count + 1)
                else:
                    return {"success": False, "error": "Rate limit excedido"}
            
            # Manejar errores de autenticación
            elif response.status_code == 401:
                return {"success": False, "error": "Token inválido"}
            
            # Manejar errores de permisos
            elif response.status_code == 403:
                return {"success": False, "error": "Sin permisos"}
                
            # Manejar respuestas exitosas
            elif response.status_code >= 200 and response.status_code < 300:
                if response.content:
                    return {"success": True, "data": response.json()}
                return {"success": True, "data": {}}
            
            # Otros errores
            else:
                if retry_count < MAX_RETRIES:
                    # Esperar un poco más en cada reintento
                    time.sleep(1 * (retry_count + 1))
                    return self.request(method, endpoint, data, retry_count + 1)
                return {"success": False, "error": f"Error {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            if retry_count < MAX_RETRIES:
                time.sleep(2 * (retry_count + 1))
                return self.request(method, endpoint, data, retry_count + 1)
            return {"success": False, "error": f"Error de conexión: {str(e)}"}
        except json.JSONDecodeError:
            return {"success": False, "error": "Error decodificando respuesta JSON"}
        except Exception as e:
            return {"success": False, "error": f"Error inesperado: {str(e)}"}
    
    def verify_token(self) -> Dict:
        """Verifica si el token es válido y obtiene datos del usuario"""
        response = self.request("GET", "/users/@me")
        if response["success"]:
            self.user_data = response["data"]
            return {"success": True, "username": self.user_data.get("username"), "id": self.user_data.get("id")}
        return response
    
    def get_guild_channels(self, guild_id: str) -> List[str]:
        """Obtiene los canales de texto de un servidor con permisos de escritura"""
        response = self.request("GET", f"/guilds/{guild_id}/channels")
        
        if not response["success"]:
            logger.error(f"Error al obtener canales: {response['error']}")
            return []
        
        channels = response["data"]
        
        # Filtrar canales de texto (tipo 0 = canal de texto)
        text_channels = [ch for ch in channels if ch['type'] == 0]
        
        # Verificar permisos (comprobación simple)
        writable_channels = []
        for ch in text_channels:
            test_response = self.request("GET", f"/channels/{ch['id']}")
            if test_response["success"]:
                writable_channels.append(ch)
        
        logger.info(f"Encontrados {len(text_channels)} canales de texto, {len(writable_channels)} con acceso")
        return [ch['id'] for ch in writable_channels]
    
    def send_message(self, channel_id: str, message: str, mention: bool = False) -> Dict:
        """Envía un mensaje a un canal específico"""
        # Preparar contenido del mensaje
        if mention and random.random() < 0.3:  # 30% de probabilidad
            message = f"@everyone {message}"
        
        payload = {"content": message}
        return self.request("POST", f"/channels/{channel_id}/messages", payload)

class DiscordSpammer:
    """Gestor principal del spam con soporte para múltiples tokens"""
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.clients = []
        self.valid_clients = []
        self.stats = {
            "sent": 0,
            "failed": 0,
            "ratelimited": 0,
            "start_time": None,
            "per_token": {}
        }
        
        # Inicializar stats por token
        for token in tokens:
            self.stats["per_token"][token] = {
                "sent": 0,
                "failed": 0,
                "ratelimited": 0
            }
        
        # Inicializar y verificar clientes
        self._init_clients()
    
    def _init_clients(self):
        """Inicializa y verifica todos los tokens"""
        logger.info(f"Verificando {len(self.tokens)} tokens...")
        
        for token in self.tokens:
            client = DiscordClient(token)
            self.clients.append(client)
            
            # Verificar token
            result = client.verify_token()
            if result["success"]:
                self.valid_clients.append(client)
                logger.info(f"✅ Token válido - Usuario: {result['username']} ({result['id']})")
            else:
                logger.error(f"❌ Token inválido: {result.get('error', 'Error desconocido')}")
        
        logger.info(f"Total de tokens válidos: {len(self.valid_clients)}/{len(self.tokens)}")
    
    def update_stats(self, token: str, status: str):
        """Actualiza las estadísticas"""
        if status == "sent":
            self.stats["sent"] += 1
            self.stats["per_token"][token]["sent"] += 1
        elif status == "failed":
            self.stats["failed"] += 1
            self.stats["per_token"][token]["failed"] += 1
        elif status == "ratelimited":
            self.stats["ratelimited"] += 1
            self.stats["per_token"][token]["ratelimited"] += 1
    
    def send_message_with_client(self, client: DiscordClient, channel_id: str, message: str, mention: bool = False) -> bool:
        """Envía un mensaje con un cliente específico"""
        response = client.send_message(channel_id, message, mention)
        
        if response["success"]:
            self.update_stats(client.token, "sent")
            return True
        elif "rate limit" in response.get("error", "").lower():
            self.update_stats(client.token, "ratelimited")
            return False
        else:
            self.update_stats(client.token, "failed")
            return False
    
    def spam_burst(self, 
                  channels: List[str], 
                  messages: List[str], 
                  limit: int, 
                  mention: bool = False, 
                  max_workers: int = DEFAULT_MAX_WORKERS) -> Dict:
        """Ejecuta un ataque de spam distribuido entre varios tokens"""
        if not self.valid_clients:
            logger.error("No hay tokens válidos para realizar la operación")
            return {"success": False, "error": "No hay tokens válidos"}
        
        self.stats["start_time"] = datetime.now()
        
        logger.info(f"Iniciando spam con {max_workers} hilos y {len(self.valid_clients)} tokens")
        
        # Crear cola de mensajes para distribuir entre tokens
        message_queue = []
        for _ in range(limit):
            client = random.choice(self.valid_clients)
            channel = random.choice(channels)
            message = random.choice(messages)
            message_queue.append((client, channel, message))
        
        # Distribuir carga entre hilos
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Enviar en lotes para mejor control
            for i in range(0, limit, BATCH_SIZE):
                batch = message_queue[i:i+BATCH_SIZE]
                futures = []
                
                for client, channel_id, msg in batch:
                    futures.append(executor.submit(
                        self.send_message_with_client, 
                        client, channel_id, msg, mention
                    ))
                
                # Esperar a que termine el lote
                for future in concurrent.futures.as_completed(futures):
                    future.result()  # Esto captura el resultado para que no se pierdan excepciones
                
                # Pausa con jitter para evitar detección de patrones
                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                
                # Mostrar progreso
                self._mostrar_progreso(limit)
                
                # Detener si alcanzamos el límite
                if self.stats["sent"] >= limit:
                    break
        
        self._mostrar_estadisticas()
        return self.stats
    
    def _mostrar_progreso(self, limit: int):
        """Muestra el progreso actual de la operación"""
        elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
        rate = self.stats["sent"] / elapsed if elapsed > 0 else 0
        progress = min(100, int(self.stats["sent"] / limit * 100))
        
        sys.stdout.write(f"\r▕{'█' * (progress // 5)}{' ' * (20 - (progress // 5))}▏ {progress}% | {self.stats['sent']}/{limit} | {rate:.2f} msg/s")
        sys.stdout.flush()
    
    def _mostrar_estadisticas(self):
        """Muestra estadísticas detalladas al finalizar"""
        elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
        
        logger.info(f"\n✅ Operación completada en {elapsed:.2f} segundos")
        logger.info(f"📊 Estadísticas globales:")
        logger.info(f"  → Mensajes enviados: {self.stats['sent']}")
        logger.info(f"  → Mensajes fallidos: {self.stats['failed']}")
        logger.info(f"  → Rate limits encontrados: {self.stats['ratelimited']}")
        logger.info(f"  → Velocidad promedio: {self.stats['sent'] / elapsed:.2f} msg/s")
        
        logger.info(f"\n📊 Estadísticas por token:")
        for i, client in enumerate(self.valid_clients):
            token = client.token
            stats = self.stats["per_token"][token]
            username = client.user_data.get("username", f"Token-{i+1}")
            logger.info(f"  → {username}: {stats['sent']} enviados, {stats['failed']} fallidos, {stats['ratelimited']} rate limits")

def guardar_configuracion(config: Dict) -> bool:
    """Guarda la configuración en un archivo JSON"""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        logger.info("✅ Configuración guardada para uso futuro")
        return True
    except Exception as e:
        logger.error(f"❌ Error al guardar configuración: {e}")
        return False

def cargar_configuracion() -> Optional[Dict]:
    """Carga la configuración desde un archivo JSON"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"❌ Error al cargar configuración: {e}")
    return None

def validar_token(token: str) -> bool:
    """Valida el formato básico de un token de Discord"""
    # Patrón básico: MTA.xxxx.xxxx (formato simplificado)
    pattern = r'^[MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}$'
    return bool(re.match(pattern, token))

def main():
    """Función principal mejorada"""
    print(f"""
██╗    ███████╗███████╗     ███████╗██████╗  █████╗ ███╗   ███╗
██║    ██╔════╝╚══███╔╝     ██╔════╝██╔══██╗██╔══██╗████╗ ████║
██║    █████╗    ███╔╝█████╗███████╗██████╔╝███████║██╔████╔██║
╚═╝    ██╔══╝   ███╔╝ ╚════╝╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║
██╗    ███████╗███████╗     ███████║██║     ██║  ██║██║ ╚═╝ ██║
╚═╝    ╚══════╝╚══════╝     ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝
          Developer: bloodyzeze.
    """)
    
    # Intentar cargar configuración guardada
    config = cargar_configuracion()
    if config:
        usar_config = input(" Se encontró una configuración guardada. ¿Usarla? (s/n): ").strip().lower()
        if usar_config == "s":
            tokens = config.get("tokens", [])
            channels = config.get("channels", [])
            messages = config.get("messages", [])
            limit = config.get("limit", 100)
            max_workers = config.get("max_workers", DEFAULT_MAX_WORKERS)
            mention = config.get("mention", False)
        else:
            config = None
    
    if not config:
        # Configuración manual
        tokens = []
        print("🔑 Ingresa tus tokens (uno por línea, escribe 'LISTO' cuando termines):")
        while True:
            token_input = input("> ").strip()
            if token_input.upper() == "LISTO":
                break
            
            if validar_token(token_input):
                tokens.append(token_input)
            else:
                print("⚠️ El formato del token parece incorrecto. Asegúrate de copiarlo correctamente.")
        
        if not tokens:
            print("❌ Debes ingresar al menos un token válido.")
            return
        
        # Inicializar spammer con múltiples tokens
        spammer = DiscordSpammer(tokens)
        
        if not spammer.valid_clients:
            print("❌ No se encontraron tokens válidos. Revisa tus tokens e intenta de nuevo.")
            return
        
        modo = input(" ¿Spamear en [1] canales específicos o [2] todos los canales de un servidor?: ").strip()
        
        if modo == "1":
            channels_input = input(" Ingresa las IDs de canales separadas por coma: ").strip()
            channels = [c.strip() for c in channels_input.split(",") if c.strip()]
        elif modo == "2":
            guild_id = input(" Ingresa la ID del servidor: ").strip()
            # Usar el primer cliente válido para obtener canales
            channels = spammer.valid_clients[0].get_guild_channels(guild_id)
            if not channels:
                print("❌ No se pudieron obtener los canales o no tienes acceso a ningún canal.")
                return
        else:
            print("❌ Opción inválida.")
            return
        
        # Configuración avanzada
        print("\n⚙️ CONFIGURACIÓN AVANZADA")
        limit_input = input(f"📈 ¿Cuántos mensajes quieres enviar en total? (por defecto: 100): ").strip()
        limit = int(limit_input) if limit_input.isdigit() else 100
        
        workers_input = input(f"🧵 ¿Cuántos hilos simultáneos? (por defecto: {DEFAULT_MAX_WORKERS}, más = más rápido pero más arriesgado): ").strip()
        max_workers = int(workers_input) if workers_input.isdigit() and int(workers_input) > 0 else DEFAULT_MAX_WORKERS
        
        mention_input = input("📣 ¿Incluir @everyone ocasionalmente? (s/n, por defecto: n): ").strip().lower()
        mention = mention_input == "s"
        
        # Mensajes a enviar
        messages = []
        print("\n🗨️ Ingresa los mensajes que quieres usar. Escribe 'LISTO' cuando termines:")
        while True:
            msg = input("> ")
            if msg.upper() == "LISTO":
                break
            if msg.strip():
                messages.append(msg.strip())
        
        if not messages:
            print("❌ Debes ingresar al menos un mensaje.")
            return
        
        # Guardar configuración
        guardar_config = input("\n💾 ¿Guardar esta configuración para uso futuro? (s/n): ").strip().lower()
        if guardar_config == "s":
            config_data = {
                "tokens": tokens,
                "channels": channels,
                "messages": messages,
                "limit": limit,
                "max_workers": max_workers,
                "mention": mention
            }
            guardar_configuracion(config_data)
    else:
        # Ya tenemos la configuración cargada
        spammer = DiscordSpammer(tokens)
    
    # Resumen y confirmar
    print("\n⚠️ RESUMEN DE LA OPERACIÓN ⚠️")
    print(f"→ Tokens válidos: {len(spammer.valid_clients)}/{len(tokens)}")
    print(f"→ Canales objetivo: {len(channels)}")
    print(f"→ Mensajes distintos: {len(messages)}")
    print(f"→ Total a enviar: {limit}")
    print(f"→ Hilos simultáneos: {max_workers}")
    print(f"→ Delay entre lotes: {MIN_DELAY} - {MAX_DELAY} segundos")
    print(f"→ Menciones @everyone: {'Activadas' if mention else 'Desactivadas'}")
    
    confirmar = input("\n⚠️ ¿Confirmar y comenzar? (s/n): ").strip().lower()
    if confirmar != "s":
        print("❌ Operación cancelada.")
        return
    
    # Ejecutar spam
    print("\n Iniciando el spam...\n")
    spammer.spam_burst(channels, messages, limit, mention, max_workers)
    
    print("\n👋 Operación completada")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⛔ Operación cancelada por el usuario")
    except Exception as e:
        logger.error(f"Error inesperado: {e}", exc_info=True)
        print(f"\n\n❌ Error inesperado: {e}")