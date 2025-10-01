import bcrypt
pw = b"mypassword"
h = bcrypt.hashpw(pw, bcrypt.gensalt())
print(h.decode())
