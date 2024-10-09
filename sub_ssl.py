import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import paho.mqtt.client as mqtt
import threading
import pandas as pd
from datetime import datetime
import time
import certifi

class MQTTSubscriberApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MQTT Subscriber")

        # Create interface
        self.create_widgets()

        # Initialize MQTT client
        self.client = mqtt.Client()

        # Dataframe for Subscriber logs
        self.sub_df = pd.DataFrame(columns=["MessageID", "Timestamp", "Payload"])

        self.sub_running = False  # Subscriber status

        # Define the MQTT callbacks
        self.client.on_message = self.on_message
        self.client.on_connect = self.on_connect

    def create_widgets(self):
        frame_sub = tk.Frame(self.root)
        frame_sub.grid(row=0, column=0, padx=10, pady=10)

        # Broker Information
        tk.Label(frame_sub, text="Broker Address").grid(row=0, column=0, padx=10, pady=5)
        self.broker_address = tk.Entry(frame_sub, width=25)
        self.broker_address.grid(row=0, column=1)
        self.broker_address.insert(0, "broker.emqx.io")  # Default value

        tk.Label(frame_sub, text="Broker Port").grid(row=1, column=0, padx=10, pady=5)
        self.broker_port = tk.Entry(frame_sub, width=25)
        self.broker_port.grid(row=1, column=1)
        self.broker_port.insert(0, "1883")  # Default value

        # CA Certificate Path
        tk.Label(frame_sub, text="CA Cert Path").grid(row=2, column=0, padx=10, pady=5)
        self.ca_cert_path = tk.Entry(frame_sub, width=25)
        self.ca_cert_path.grid(row=2, column=1)
        self.ca_cert_path.insert(0, "broker.emqx.io-ca.crt")  # Default value

        # Connection Type
        tk.Label(frame_sub, text="Connection Type").grid(row=3, column=0, padx=10, pady=5)
        self.connection_type = ttk.Combobox(frame_sub, values=["TCP", "SSL/TLS"], width=23)
        self.connection_type.grid(row=3, column=1)
        self.connection_type.current(0)  # Default to TCP

        # Subscriber Section
        tk.Label(frame_sub, text="Subscriber Topic").grid(row=4, column=0, padx=10, pady=5)
        self.sub_topic = tk.Entry(frame_sub, width=25)
        self.sub_topic.grid(row=4, column=1)

        tk.Label(frame_sub, text="QoS").grid(row=5, column=0, padx=10, pady=5)
        self.sub_qos = ttk.Combobox(frame_sub, values=[0, 1, 2], width=23)
        self.sub_qos.grid(row=5, column=1)
        self.sub_qos.current(0)  # Default value

        tk.Button(frame_sub, text="Start Subscriber", command=self.start_subscriber).grid(row=6, column=0, padx=10, pady=5)
        tk.Button(frame_sub, text="Stop Subscriber", command=self.stop_subscriber).grid(row=6, column=1, padx=10, pady=5)

        # Log output for Subscriber
        tk.Label(frame_sub, text="Subscriber Log").grid(row=7, column=0, columnspan=2, padx=10, pady=5)
        self.sub_log_area = scrolledtext.ScrolledText(frame_sub, width=60, height=10)
        self.sub_log_area.grid(row=8, column=0, columnspan=2, padx=10, pady=5)

    def log_message_sub(self, message):
        self.sub_log_area.insert(tk.END, message + "\n")
        self.sub_log_area.yview(tk.END)

    def start_subscriber(self):
        if not self.sub_running:
            self.sub_running = True
            self.sub_thread = threading.Thread(target=self.subscriber_loop)
            self.sub_thread.start()
        else:
            self.log_message_sub("Subscriber is already running.")

    def stop_subscriber(self):
        if self.sub_running:
            self.sub_running = False
            self.log_message_sub("Subscriber has been stopped.")
        else:
            self.log_message_sub("Subscriber is not running.")

    def on_connect(self, client, userdata, flags, rc):
        topic = self.sub_topic.get()
        qos = int(self.sub_qos.get())
        client.subscribe(topic, qos=qos)
        self.log_message_sub(f"Connected to broker, subscribed to '{topic}' with QoS {qos}")

    def on_message(self, client, userdata, message):
        payload = message.payload.decode()
        timestamp = datetime.now().strftime('%H:%M:%S.%f')
        message_id = len(self.sub_df) + 1  # Simple message ID based on DataFrame length

        # Log received message
        self.sub_df = pd.concat([self.sub_df, pd.DataFrame([{
            "MessageID": message_id,
            "Timestamp": timestamp,
            "Payload": payload
        }])], ignore_index=True)

        self.log_message_sub(f"Received: {payload} at {timestamp}")

    def subscriber_loop(self):
        broker_address = self.broker_address.get()
        broker_port = int(self.broker_port.get())
        ca_cert = self.ca_cert_path.get()

        # Configure TLS/SSL if selected
        if self.connection_type.get() == "SSL/TLS":
            ca_cert = certifi.where()  # Use certifi's CA certificates
            self.client.tls_set(ca_certs=ca_cert)  # Set the CA certificate
            broker_port = 8883  # Use the SSL port

        try:
            self.client.connect(broker_address, broker_port, 60)
            self.client.loop_start()  # Start the MQTT loop
        except Exception as e:
            self.log_message_sub(f"Failed to connect to broker: {e}")
            return

        while self.sub_running:
            time.sleep(1)  # Keep the loop running

        self.client.loop_stop()  # Stop the MQTT loop
        self.sub_df.to_csv('subscriber_log.txt', index=False, sep='\t', mode='w')

if __name__ == "__main__":
    root = tk.Tk()
    app = MQTTSubscriberApp(root)
    root.mainloop()
