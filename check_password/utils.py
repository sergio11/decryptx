# -*- coding: utf-8 -*-

def parse_string(string):
	if type(string) == str:
		# Given a string of length one, return an integer representing the Unicode code point of the character
		mayus = 0
		minus = 0
		nums = 0
		especial = 0
		for char in string:
			# check number 0-9
			if ord(char) >= 48 and ord(char) <= 57:
				nums += 1
			# check capital letter A-Z
			elif ord(char) >= 65 and ord(char) <= 90:
				mayus += 1
			# check lower letter a-z
			elif ord(char) >= 97 and ord(char) <= 122:
				minus += 1
			# special character
			else:
				especial += 1
		# return dictionary
		return {
			'mayus': mayus,
			'minus': minus,
			'nums': nums,
			'especial': especial
		}

	else:
		print "string debe ser una cadena "

def check_password(password,constraints):
	valid = False
	if type(password) == str and type(constraints) == dict:
		if len(password) >= constraints['min-leng']:
			# analizamos la cadena
			result = parse_string(password)
			print "La cadena contiene:"
			print result['mayus'],"/",constraints['min-mayus']," mayúsculas."
			print result['minus'],"/",constraints['min-minus']," minúsculas."
			print result['especial'],"/",constraints['min-special'], " carácteres especiales."
			print result['nums'],"/", constraints['min-number']," números."  
			# comprobamos resto de restricciones 
			if result['mayus'] >= constraints['min-mayus'] and result['minus'] >= constraints['min-minus'] and result['especial'] >= constraints['min-special'] and result['nums'] >= constraints['min-number']:
			   valid = True
	else:
		print "Password debe ser un string y constraints debe ser un diccionario "

	return valid
	
	