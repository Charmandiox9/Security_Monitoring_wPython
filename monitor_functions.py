import psutil
import logging
import GPUtil
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

# Configuración de logging
def create_logger(log_filename):
    logger = logging.getLogger(log_filename)
    handler = logging.FileHandler(log_filename)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

# Función para loguear eventos
def log_event(event, log_filename):
    logger = create_logger(log_filename)
    logger.info(event)

# Monitoreo de uso de CPU y memoria
def monitor_cpu_memory(stop_event, text_widget):
    log_filename = 'cpu_memory_log.txt'
    while not stop_event.is_set():
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        gpus = GPUtil.getGPUs()
        gpu_usage = gpus[0].memoryUtil * 100 if gpus else 0
        message = f"CPU: {cpu_usage}%, Memoria: {memory_info.percent}%, GPU: {gpu_usage}%"
        text_widget.insert('end', message + "\n")
        log_event(message, log_filename)
        time.sleep(5)

# Monitoreo de cambios en la configuración de red
def monitor_network_config(stop_event, text_widget):
    log_filename = 'network_config_log.txt'
    previous_config = psutil.net_if_addrs()
    while not stop_event.is_set():
        current_config = psutil.net_if_addrs()
        if current_config != previous_config:
            message = "Cambio en configuración de red detectado."
            text_widget.insert('end', message + "\n")
            log_event(message, log_filename)
            previous_config = current_config
        time.sleep(5)

# Monitoreo de actividad en puertos específicos
def monitor_specific_ports(stop_event, text_widget, ports=[80, 443, 22]):
    log_filename = 'specific_ports_log.txt'
    text_widget.insert('end', f"Monitoreando puertos: {ports}\n")
    while not stop_event.is_set():
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port in ports and conn.status == 'ESTABLISHED':
                message = f"Actividad en puerto {conn.laddr.port}: {conn.status}"
                text_widget.insert('end', message + "\n")
                log_event(message, log_filename)
        time.sleep(5)

# Monitoreo de conexiones entrantes y salientes
def monitor_incoming_outgoing_connections(stop_event, text_widget):
    log_filename = 'incoming_outgoing_connections_log.txt'
    while not stop_event.is_set():
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                message = f"Conexión {conn.status} desde {conn.laddr} hacia {conn.raddr}"
                text_widget.insert('end', message + "\n")
                log_event(message, log_filename)
        time.sleep(5)

# Monitoreo de cambios en archivos
def monitor_files(path, stop_event, text_widget):
    log_filename = 'file_changes_log.txt'
    class FileChangeHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            if stop_event.is_set():
                return
            message = f"{event.event_type.title()} en {event.src_path}"
            text_widget.insert('end', message + "\n")
            log_event(message, log_filename)

    observer = Observer()
    observer.schedule(FileChangeHandler(), path=path, recursive=True)
    observer.start()
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

# Monitoreo de procesos del sistema (ejecuta solo una vez)
def monitor_processes(stop_event, text_widget):
    log_filename = 'processes_log.txt'
    text_widget.insert('end', "Monitoreo de procesos activos:\n")
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        if stop_event.is_set():
            break
        message = f"Proceso: {process.info}"
        text_widget.insert('end', message + "\n")
        log_event(message, log_filename)
    text_widget.insert('end', "Monitoreo de procesos completado.\n")
