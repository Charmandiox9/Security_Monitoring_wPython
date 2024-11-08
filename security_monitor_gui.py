import tkinter as tk
import threading
from tkinter import filedialog, messagebox, Scrollbar, Text, scrolledtext
import monitor_functions as mf

# Configuración de control de hilos
stop_threads = threading.Event()

# Funciones para iniciar y detener monitoreos en hilos
def start_monitor_files(output_text):
    path = filedialog.askdirectory()
    if not path:
        messagebox.showerror("Error", "Selecciona una carpeta para monitorear.")
        return
    stop_threads.clear()
    threading.Thread(target=mf.monitor_files, args=(path, stop_threads, output_text), daemon=True).start()

def start_monitor_network_config(output_text):
    stop_threads.clear()
    threading.Thread(target=mf.monitor_network_config, args=(stop_threads, output_text), daemon=True).start()

def start_monitor_specific_ports(output_text):
    stop_threads.clear()
    threading.Thread(target=mf.monitor_specific_ports, args=(stop_threads, output_text), daemon=True).start()

def start_monitor_incoming_outgoing_connections(output_text):
    stop_threads.clear()
    threading.Thread(target=mf.monitor_incoming_outgoing_connections, args=(stop_threads, output_text), daemon=True).start()

def start_monitor_cpu_memory(output_text):
    stop_threads.clear()
    threading.Thread(target=mf.monitor_cpu_memory, args=(stop_threads, output_text), daemon=True).start()

def start_monitor_processes(output_text):
    stop_threads.clear()
    threading.Thread(target=mf.monitor_processes, args=(stop_threads, output_text), daemon=True).start()

# Función para detener el monitoreo
def stop_monitoring():
    stop_threads.set()
    messagebox.showinfo("Detener Monitoreo", "Los monitoreos se están deteniendo...")

# Función para limpiar el cuadro de texto de salida
def clear_output(output_text):
    output_text.delete(1.0, tk.END)

# Crear y configurar la interfaz gráfica
def create_app():
    app = tk.Tk()
    app.title("Monitoreo de Seguridad")
    app.geometry("800x600")
    app.resizable(False, False)
    screen_width, screen_height = app.winfo_screenwidth(), app.winfo_screenheight()
    position_x, position_y = (screen_width - 800) // 2, (screen_height - 600) // 2
    app.geometry(f"800x600+{position_x}+{position_y}")
    app.iconbitmap("ucenin.ico")
    app.configure(bg="#6e6e6e")

    # Botones para monitoreo
    button_frame = tk.Frame(app)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="CPU y Memoria", command=lambda: start_monitor_cpu_memory(output_text), width=25, height=2).grid(row=0, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Configuración de Red", command=lambda: start_monitor_network_config(output_text), width=25, height=2).grid(row=0, column=1, padx=10, pady=5)
    tk.Button(button_frame, text="Puertos Específicos", command=lambda: start_monitor_specific_ports(output_text), width=25, height=2).grid(row=0, column=2, padx=10, pady=5)
    tk.Button(button_frame, text="Conexiones", command=lambda: start_monitor_incoming_outgoing_connections(output_text), width=25, height=2).grid(row=1, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Cambios en Archivos", command=lambda: start_monitor_files(output_text), width=25, height=2).grid(row=1, column=1, padx=10, pady=5)
    tk.Button(button_frame, text="Procesos del Sistema", command=lambda: start_monitor_processes(output_text), width=25, height=2).grid(row=1, column=2, padx=10, pady=5)
    tk.Button(button_frame, text="Detener Monitoreo", command=stop_monitoring, font=("Arial", 10, "bold"), width=25, height=2).grid(row=2, column=0, padx=10, pady=5)
    tk.Button(button_frame, text="Limpiar Salida", command=lambda: clear_output(output_text), font=("Arial", 10, "bold"), width=25, height=2).grid(row=2, column=2, padx=10, pady=5)

    # Cuadro de texto de salida con scrollbar
    output_frame = tk.Frame(app)
    output_frame.pack(fill="both", expand=True, padx=10, pady=10)

    output_text = scrolledtext.ScrolledText(output_frame, wrap="word", font=("Arial", 10), height=20, width=90)
    output_text.pack(fill="both", expand=True)
    output_text.config(bg="#f4f4f4", bd=0, padx=10, pady=10)

    return app

if __name__ == "__main__":
    app = create_app()
    app.mainloop()
