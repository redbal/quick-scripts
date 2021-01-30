import ssl
import sys

import paho.mqtt.client

def on_connect(client, userdata, flags, rc):
	print('connected (%s)' % client._client_id)
	client.subscribe("TEST", 2)

def on_message(client, userdata, message):
	print('------------------------------')
	print('topic: %s' % message.topic)
	print('payload: %s' % message.payload)
	print('qos: %d' % message.qos)

def main():
	client = paho.mqtt.client.Client(client_id='[clientid]', clean_session=False)
	client.username_pw_set('[username]', '[password]')
	client.on_connect = on_connect
	client.on_message = on_message
	client.tls_set('/home/credd/ca-certificates.crt', tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)
	client.connect('reddtech.us', 8883, 60)
	#client.loop_forever()
	client.loop_forever()

if __name__ == '__main__':
	main()
	sys.exit(0)
