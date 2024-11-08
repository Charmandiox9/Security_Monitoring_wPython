import psutil
import logging
import tkinter as tk
import threading
import time
import GPUtil
from tkinter import filedialog, messagebox
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Configuración de logging
logging.basicConfig(filename='security_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Variable para controlar los hilos de monitoreo
stop_threads = threading.Event()


# Función para crear archivos de log según el tipo de monitoreo
def create_logger(log_filename):
    logger = logging.getLogger(log_filename)
    handler = logging.FileHandler(log_filename)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


# Función para loguear eventos de monitoreo
def log_event(event, log_filename):
    logger = create_logger(log_filename)
    logger.info(f"Evento de seguridad: {event}")


# Monitoreo de uso de CPU y memoria
def monitor_cpu_memory(text_widget):
    log_filename = 'cpu_memory_log.txt'  # Archivo específico para CPU y memoria
    while not stop_threads.is_set():
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        gpus = GPUtil.getGPUs()
        gpu_usage = 0
        if gpus:  # Si se detecta alguna GPU
            gpu_usage = gpus[0].memoryUtil * 100  # Usamos el primer GPU (si hay más, puedes ajustar esto)
        message = f"Uso de CPU: {cpu_usage}% - Uso de Memoria: {memory_info.percent}% - Uso de GPU: {gpu_usage}%"
        text_widget.insert(tk.END, message + "\n")
        log_event(message, log_filename)
        #time.sleep(5)  # Monitoreo cada 5 segundos

# Monitoreo de cambios en la configuración de red
def monitor_network_config(text_widget):
    log_filename = 'network_config_log.txt'  # Archivo específico para configuración de red
    previous_config = psutil.net_if_addrs()
    while not stop_threads.is_set():
        current_config = psutil.net_if_addrs()
        if current_config != previous_config:
            message = "Cambio detectado en la configuración de red."
            text_widget.insert(tk.END, message + "\n")
            log_event(message, log_filename)
            previous_config = current_config
        #time.sleep(5)  # Monitoreo cada 5 segundos

# Monitoreo de actividad en puertos específicos
def monitor_specific_ports(text_widget, ports=[80, 443, 22]):
    log_filename = 'specific_ports_log.txt'  # Archivo específico para puertos
    text_widget.insert(tk.END, f"Monitoreo de actividad en los puertos: {ports}\n")
    while not stop_threads.is_set():
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port in ports and conn.status == 'ESTABLISHED':
                message = f"Actividad detectada en puerto {conn.laddr.port}: {conn.status}"
                text_widget.insert(tk.END, message + "\n")
                log_event(message, log_filename)
        #time.sleep(5)

# Monitoreo de conexiones salientes y entrantes
def monitor_incoming_outgoing_connections(text_widget):
    log_filename = 'incoming_outgoing_connections_log.txt'  # Archivo específico para conexiones
    text_widget.insert(tk.END, "Iniciando monitoreo de conexiones salientes y entrantes...\n")
    while not stop_threads.is_set():
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                message = f"Conexión {conn.status} desde {conn.laddr} hacia {conn.raddr}"
                text_widget.insert(tk.END, message + "\n")
                log_event(message, log_filename)
        #time.sleep(5)

# Monitoreo de cambios en archivos
def monitor_files(path, text_widget):
    log_filename = 'file_changes_log.txt'  # Archivo específico para cambios en archivos
    class FileChangeHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if stop_threads.is_set():
                return
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            message = f"{current_time} - Archivo modificado: {event.src_path}"
            text_widget.insert(tk.END, message + "\n")
            log_event(message, log_filename)

        def on_created(self, event):
            if stop_threads.is_set():
                return
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            message = f"{current_time} - Archivo creado: {event.src_path}"
            text_widget.insert(tk.END, message + "\n")
            log_event(message, log_filename)

        def on_deleted(self, event):
            if stop_threads.is_set():
                return
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            message = f"{current_time} - Archivo eliminado: {event.src_path}"
            text_widget.insert(tk.END, message + "\n")
            log_event(message, log_filename)

    observer = Observer()
    observer.schedule(FileChangeHandler(), path=path, recursive=True)
    observer.start()
    text_widget.insert(tk.END, f"Monitoreo de archivos iniciado en {path}. Cierra la ventana para detener.\n")
    
    try:
        while not stop_threads.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

# Monitoreo de tráfico de red
def monitor_network(text_widget):
    log_filename = 'network_traffic_log.txt'  # Archivo específico para tráfico de red
    def packet_callback(packet):
        if stop_threads.is_set():
            return True  # Detiene el sniffing si se ha activado `stop_threads`
        message = f"Paquete detectado: {packet.summary()}"
        text_widget.insert(tk.END, message + "\n")
        log_event(message, log_filename)

    text_widget.insert(tk.END, "Iniciando monitoreo de red...\n")
    sniff(filter="tcp", prn=packet_callback, stop_filter=lambda x: stop_threads.is_set())

# Monitoreo de procesos del sistema (ejecuta solo una vez)
def monitor_processes(text_widget):
    log_filename = 'processes_log.txt'  # Archivo específico para procesos
    text_widget.insert(tk.END, "Monitoreo de procesos activos:\n")
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        if stop_threads.is_set():
            break
        message = f"Proceso: {process.info}"
        text_widget.insert(tk.END, message + "\n")
        log_event(message, log_filename)
    text_widget.insert(tk.END, "Monitoreo de procesos completado.\n")

# Monitoreo de puertos abiertos (ejecuta solo una vez)
def monitor_ports(text_widget):
    log_filename = 'open_ports_log.txt'  # Archivo específico para puertos abiertos
    text_widget.insert(tk.END, "Monitoreo de puertos abiertos:\n")
    for conn in psutil.net_connections(kind='inet'):
        if stop_threads.is_set():
            break
        message = f"Puerto: {conn.laddr.port} - Estado: {conn.status}"
        text_widget.insert(tk.END, message + "\n")
        log_event(message, log_filename)
    text_widget.insert(tk.END, "Monitoreo de puertos completado.\n")


# Función para detener el monitoreo
def stop_monitoring():
    stop_threads.set()
    messagebox.showinfo("Detener Monitoreo", "Los monitoreos se están deteniendo...")


# Función para limpiar el cuadro de texto de salida
def clear_output(output_text):
    output_text.delete(1.0, tk.END)


# Funciones para iniciar cada monitoreo en un hilo separado
def start_monitor_files(output_text):
    path = filedialog.askdirectory()
    if not path:
        messagebox.showerror("Error", "Por favor, selecciona una carpeta para monitorear archivos.")
        return
    stop_threads.clear()  # Reiniciar la señal de parada
    threading.Thread(target=monitor_files, args=(path, output_text), daemon=True).start()

def start_monitor_network(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_network, args=(output_text,), daemon=True).start()

def start_monitor_processes(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_processes, args=(output_text,), daemon=True).start()

def start_monitor_ports(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_ports, args=(output_text,), daemon=True).start()

def start_monitor_cpu_memory(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_cpu_memory, args=(output_text,), daemon=True).start()

def start_monitor_network_config(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_network_config, args=(output_text,), daemon=True).start()

def start_monitor_specific_ports(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_specific_ports, args=(output_text,), daemon=True).start()

def start_monitor_incoming_outgoing_connections(output_text):
    stop_threads.clear()
    threading.Thread(target=monitor_incoming_outgoing_connections, args=(output_text,), daemon=True).start()


# Función para crear y configurar la ventana de la aplicación
def create_app():
    app = tk.Tk()
    app.title("Monitoreo de Seguridad")
    app.iconbitmap("ucenin.ico")
    app.configure(bg="#ddd4de")

    # Tamaño de la ventana
    window_width = 800
    window_height = 600
    app.geometry(f"{window_width}x{window_height}")
    app.resizable(False, False)

    # Centrar la ventana en la pantalla
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    position_x = (screen_width - window_width) // 2
    position_y = (screen_height - window_height) // 2
    app.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

    # Marco para los botones
    button_frame = tk.Frame(app)
    button_frame.pack(pady=10)

    # Configurar las columnas de la cuadrícula para que se expandan proporcionalmente
    button_frame.grid_columnconfigure(0, weight=1)
    button_frame.grid_columnconfigure(1, weight=1)
    button_frame.grid_columnconfigure(2, weight=1)

    # Botones para cada tipo de monitoreo, organizados en una cuadrícula
    tk.Button(button_frame, text="Monitoreo de CPU y Memoria", command=lambda: start_monitor_cpu_memory(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=0, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Configuración de Red", command=lambda: start_monitor_network_config(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=0, column=1, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Puertos", command=lambda: start_monitor_specific_ports(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=0, column=2, padx=10, pady=5)
    tk.Button(button_frame, text="Conexiones Entrantes/Salientes", command=lambda: start_monitor_incoming_outgoing_connections(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=1, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Cambios en Archivos", command=lambda: start_monitor_files(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=1, column=1, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Tráfico de Red", command=lambda: start_monitor_network(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=1, column=2, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Procesos del Sistema", command=lambda: start_monitor_processes(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=2, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Monitoreo de Puertos Abiertos", command=lambda: start_monitor_ports(output_text), bg="grey", fg="white", font=("Arial", 10), width=25, height=2).grid(row=2, column=2, padx=10, pady=5)

    # Botón para detener todos los monitoreos
    tk.Button(button_frame, text="Detener Monitoreo", command=stop_monitoring, bg="#6e6e6e", fg="white", font=("Arial", 12, "bold"), width=20, height=2).grid(row=3, column=0, padx= 20, pady=25)

    # Botón para limpiar el cuadro de salida
    tk.Button(button_frame, text="Limpiar Salida", command=lambda: clear_output(output_text), bg="#6e6e6e", fg="white", font=("Arial", 12, "bold"), width=20, height=2).grid(row=3, column=2, padx= 20, pady=25)

    # Cuadro de texto con barra de desplazamiento para la salida de los resultados
    output_frame = tk.Frame(app)
    output_frame.pack()

    scrollbar = tk.Scrollbar(output_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    output_text = tk.Text(output_frame, height=15, width=80, wrap="word", font=("Arial", 10), yscrollcommand=scrollbar.set)
    output_text.pack()
    scrollbar.config(command=output_text.yview)

    return app

# Configuración principal
if __name__ == "__main__":
    app = create_app()
    app.mainloop()
