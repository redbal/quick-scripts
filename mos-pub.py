import time
import paho.mqtt.client as paho
import ssl

#define callbacks
def on_message(client, userdata, message):
  print("received message =",str(message.payload.decode("utf-8")))

def on_log(client, userdata, level, buf):
  print("log: ",buf)

def on_connect(client, userdata, flags, rc):
  print("publishing ")
  client.publish("TEST","TEST",)


client=paho.Client() 
client.on_message=on_message
client.on_log=on_log
client.on_connect=on_connect
#client.username_pw_set('[]', '[]') #NEED THIS
print("connecting to broker")
client.tls_set("/etc/ssl/certs/ca-certificates.crt", tls_version=ssl.PROTOCOL_TLSv1_2)
#client.tls_insecure_set(True)
client.connect("reddtech.us", 8883, 60)

##start loop to process received messages
client.loop_start()
#wait to allow publish and logging and exit
time.sleep(1)
