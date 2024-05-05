import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import psutil
import datetime
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import os

def send_email_notification(sender_email, password, receiver_email, subject, message, attachment_path=None):
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    msg.attach(MIMEText(message, "plain"))

    if attachment_path:
        with open(attachment_path, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
        part["Content-Disposition"] = f"attachment; filename={os.path.basename(attachment_path)}"
        msg.attach(part)

    try:
        with smtplib.SMTP_SSL("smtp.mail.ru", 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

class EmailWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Email Configuration")

        self.sender_email_label = ttk.Label(self, text="Sender Email:")
        self.sender_email_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.sender_email_entry = ttk.Entry(self)
        self.sender_email_entry.grid(row=0, column=1, padx=5, pady=5)

        self.sender_password_label = ttk.Label(self, text="Sender Password:")
        self.sender_password_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.sender_password_entry = ttk.Entry(self, show="*")
        self.sender_password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.recipient_email_label = ttk.Label(self, text="Recipient Email:")
        self.recipient_email_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.recipient_email_entry = ttk.Entry(self)
        self.recipient_email_entry.grid(row=2, column=1, padx=5, pady=5)

        self.send_button = ttk.Button(self, text="Send", command=self.send_email)
        self.send_button.grid(row=3, columnspan=2, padx=5, pady=5)

    def send_email(self):
        sender_email = self.sender_email_entry.get()
        sender_password = self.sender_password_entry.get()
        recipient_email = self.recipient_email_entry.get()

        if sender_email and sender_password and recipient_email:
            try:
                send_email_notification(sender_email, sender_password, recipient_email, "Process Monitor - Processes", "Please find attached the processes file.", "processes.txt")
                messagebox.showinfo("Success", "Email sent successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

class ProcessMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Monitor")
        
        self.tree_frame = ttk.Frame(self.root)
        self.tree_frame.pack(fill="both", expand=True)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=("name", "cpu_percent", "memory_percent", "user", "datetime"))
        self.tree.heading("#0", text="PID")
        self.tree.heading("name", text="Name")
        self.tree.heading("cpu_percent", text="CPU %")
        self.tree.heading("memory_percent", text="Memory %")
        self.tree.heading("user", text="User")
        self.tree.heading("datetime", text="Date Time")
        
        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        
        self.start_button = tk.Button(self.root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=5, pady=5)
        
        self.pause_button = tk.Button(self.root, text="Pause Monitoring", command=self.pause_monitoring, state="disabled")
        self.pause_button.pack(side="left", padx=5, pady=5)
        
        self.resume_button = tk.Button(self.root, text="Resume Monitoring", command=self.resume_monitoring, state="disabled")
        self.resume_button.pack(side="left", padx=5, pady=5)
        
        self.stop_button = tk.Button(self.root, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", padx=5, pady=5)
        
        self.kill_button = tk.Button(self.root, text="Kill Process", command=self.kill_process, state="disabled")
        self.kill_button.pack(side="left", padx=5, pady=5)
        
        self.save_button = tk.Button(self.root, text="Save Processes", command=self.save_processes)
        self.save_button.pack(side="left", padx=5, pady=5)
        
        self.send_button = tk.Button(self.root, text="Send to Email", command=self.open_email_window)
        self.send_button.pack(side="left", padx=5, pady=5)
        
        self.monitoring = False
        self.paused = False
        self.update_interval = 1  # Update interval in seconds
        
        self.monitor_thread = None
        self.processes = {}  # Dictionary to store process information

    def start_monitoring(self):
        self.monitoring = True
        self.paused = False
        self.start_button.config(state="disabled")
        self.pause_button.config(state="normal")
        self.stop_button.config(state="normal")
        self.kill_button.config(state="normal")
        
        self.monitor_thread = threading.Thread(target=self.monitor_processes)
        self.monitor_thread.start()

    def pause_monitoring(self):
        self.paused = True
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="normal")

    def resume_monitoring(self):
        self.paused = False
        self.pause_button.config(state="normal")
        self.resume_button.config(state="disabled")
        self.root.after_idle(self.monitor_processes)  # Resume monitoring immediately after the pause

    def stop_monitoring(self):
        self.monitoring = False
        self.paused = False
        self.start_button.config(state="normal")
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="disabled")
        self.stop_button.config(state="disabled")
        self.kill_button.config(state="disabled")

    def kill_process(self):
        selected_item = self.tree.selection()
        if selected_item:
            pid = self.tree.item(selected_item)["text"]
            try:
                process = psutil.Process(int(pid))
                process.kill()
                self.tree.delete(selected_item)
            except psutil.NoSuchProcess:
                pass

    def save_processes(self):
        with open("processes.txt", "w") as f:
            for item in self.tree.get_children():
                pid = self.tree.item(item)["text"]
                values = self.tree.item(item)["values"]
                f.write(f"PID: {pid}\n")
                f.write(f"Name: {values[0]}\n")
                f.write(f"CPU %: {values[1]}\n")
                f.write(f"Memory %: {values[2]}\n")
                f.write(f"User: {values[3]}\n")
                f.write(f"Date Time: {values[4]}\n\n")
        print("Processes saved successfully.")

    def open_email_window(self):
        email_window = EmailWindow(self.root)

    def monitor_processes(self):
        if not self.monitoring:
            return
        while self.paused:
            self.root.update()  # Ensure GUI responsiveness during pause
            self.root.after(100)  # Check every 100 milliseconds if paused flag has changed
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            pid = str(proc.info['pid'])
            if pid not in self.processes:
                self.processes[pid] = proc.info
                self.tree.insert("", "end", text=pid, values=(
                    proc.info['name'],
                    f"{proc.info['cpu_percent']:.2f}",
                    f"{proc.info['memory_percent']:.2f}",
                    proc.info['username'],
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
            else:
                # Update existing process info
                item = self.tree.get_children()[list(self.processes.keys()).index(pid)]
                self.tree.item(item, values=(
                    proc.info['name'],
                    f"{proc.info['cpu_percent']:.2f}",
                    f"{proc.info['memory_percent']:.2f}",
                    proc.info['username'],
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
        if self.monitoring:
            self.root.after(self.update_interval * 1000, self.monitor_processes)  # Schedule next monitoring iteration

def main():
    root = tk.Tk()
    app = ProcessMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
