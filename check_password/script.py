# -*- coding: utf-8 -*-
# Pedimos password
from utils import check_password
import hashlib

constraints = {
	'min-leng': 10,
	'min-mayus': 1,
	'min-minus': 1,
	'min-special': 1,
	'min-number': 2
}

password = input("Introduce una password :")
while(not check_password(password,constraints)):
	print "Las password no cumple con los requisitos"
	password = input("Introduce una password :")
print "La password introducida fue ", password
print "Este es el hash md5 de tu password ",hashlib.md5(password).digest()

