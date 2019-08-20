import socket

def is_port_up(ip, port, timeout = 1, throw = False):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(timeout)
	try:
		s.connect((ip, int(port)))
		s.shutdown(socket.SHUT_RDWR)
		return True
	except Exception as e:
		if throw is True:
			raise e
		return False
	finally:
		s.close()