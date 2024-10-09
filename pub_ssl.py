import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import paho.mqtt.client as mqtt
import threading
import time
import random
import pandas as pd
from datetime import datetime
import certifi

class MQTTPublisherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MQTT Publisher")

        # Create interface
        self.create_widgets()

        # Initialize MQTT client
        self.client = mqtt.Client()

        # Dataframe for Publisher logs
        self.pub_df = pd.DataFrame(columns=["MessageID", "Count", "Timestamp", "Payload"])

        self.pub_running = False  # Publisher status

    def create_widgets(self):
        frame_pub = tk.Frame(self.root)
        frame_pub.grid(row=0, column=0, padx=10, pady=10)

        # Broker Information
        tk.Label(frame_pub, text="Broker Address").grid(row=0, column=0, padx=10, pady=5)
        self.broker_address = tk.Entry(frame_pub, width=25)
        self.broker_address.grid(row=0, column=1)
        self.broker_address.insert(0, "broker.emqx.io")  # Default value

        tk.Label(frame_pub, text="Broker Port").grid(row=1, column=0, padx=10, pady=5)
        self.broker_port = tk.Entry(frame_pub, width=25)
        self.broker_port.grid(row=1, column=1)
        self.broker_port.insert(0, "1883")  # Default value

        # CA Certificate Path
        tk.Label(frame_pub, text="CA Cert Path").grid(row=2, column=0, padx=10, pady=5)
        self.ca_cert_path = tk.Entry(frame_pub, width=25)
        self.ca_cert_path.grid(row=2, column=1)
        self.ca_cert_path.insert(0, "broker.emqx.io-ca.crt")  # Default value

        # Connection Type
        tk.Label(frame_pub, text="Connection Type").grid(row=3, column=0, padx=10, pady=5)
        self.connection_type = ttk.Combobox(frame_pub, values=["TCP", "SSL/TLS"], width=23)
        self.connection_type.grid(row=3, column=1)
        self.connection_type.current(0)  # Default to TCP

        # Publisher Section
        tk.Label(frame_pub, text="Publisher Topic").grid(row=4, column=0, padx=10, pady=5)
        self.pub_topic = tk.Entry(frame_pub, width=25)
        self.pub_topic.grid(row=4, column=1)

        tk.Label(frame_pub, text="Publish Interval (s)").grid(row=5, column=0, padx=10, pady=5)
        self.pub_interval = tk.Entry(frame_pub, width=25)
        self.pub_interval.grid(row=5, column=1)
        self.pub_interval.insert(0, "1")  # Default interval

        tk.Label(frame_pub, text="QoS").grid(row=6, column=0, padx=10, pady=5)
        self.pub_qos = ttk.Combobox(frame_pub, values=[0, 1, 2], width=23)
        self.pub_qos.grid(row=6, column=1)
        self.pub_qos.current(0)  # Default value

        tk.Button(frame_pub, text="Start Publisher", command=self.start_publisher).grid(row=7, column=0, padx=10, pady=5)
        tk.Button(frame_pub, text="Stop Publisher", command=self.stop_publisher).grid(row=7, column=1, padx=10, pady=5)

        # Log output for Publisher
        tk.Label(frame_pub, text="Publisher Log").grid(row=8, column=0, columnspan=2, padx=10, pady=5)
        self.pub_log_area = scrolledtext.ScrolledText(frame_pub, width=60, height=10)
        self.pub_log_area.grid(row=9, column=0, columnspan=2, padx=10, pady=5)

    def log_message_pub(self, message):
        self.pub_log_area.insert(tk.END, message + "\n")
        self.pub_log_area.yview(tk.END)

    def start_publisher(self):
        if not self.pub_running:
            self.pub_running = True
            self.pub_thread = threading.Thread(target=self.publisher_loop)
            self.pub_thread.start()
        else:
            self.log_message_pub("Publisher is already running.")

    def stop_publisher(self):
        if self.pub_running:
            self.pub_running = False
            self.log_message_pub("Publisher has been stopped.")
        else:
            self.log_message_pub("Publisher is not running.")

    def publisher_loop(self):
        message_count = 1
        topic = self.pub_topic.get()
        interval = float(self.pub_interval.get())
        broker_address = self.broker_address.get()
        broker_port = int(self.broker_port.get())
        qos = int(self.pub_qos.get())
        ca_cert = self.ca_cert_path.get()

        # Configure TLS/SSL if selected
        if self.connection_type.get() == "SSL/TLS":
            ca_cert = certifi.where()  # Use certifi's CA certificates
            self.client.tls_set(ca_certs=ca_cert)  # Set the CA certificate
            broker_port = 8883  # Use the SSL port

        try:
            self.client.on_publish = self.on_publish  # Assign publish callback
            self.client.connect(broker_address, broker_port, 60)
            self.client.loop_start()  # Start the loop
        except Exception as e:
            self.log_message_pub(f"Failed to connect to broker: {e}")
            return

        while self.pub_running:
            payload = f"{message_count},{random.randint(-300, 300)}"
            timestamp = datetime.now().strftime('%H:%M:%S.%f')

            result = self.client.publish(topic, payload, qos=qos)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.pub_df = pd.concat([self.pub_df, pd.DataFrame([{
                    "MessageID": message_count,
                    "Count": message_count,
                    "Timestamp": timestamp,
                    "Payload": payload
                }])], ignore_index=True)

                self.log_message_pub(f"Published: {payload} (ID: {message_count}) to topic '{topic}' at {timestamp} with QoS {qos}")
            else:
                self.log_message_pub(f"Failed to publish message: {result.rc}")

            message_count += 1
            time.sleep(interval)

        self.client.loop_stop()  # Stop the loop
        self.client.disconnect()
        self.pub_df.to_csv('publisher_log.txt', index=False, sep='\t', mode='w')

    def on_publish(self, client, userdata, mid):
        self.log_message_pub(f"Message {mid} published.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MQTTPublisherApp(root)
    root.mainloop()
