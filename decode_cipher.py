with open("./ciphertext.txt", "rb") as f:
    data = f.read()
    print(data.hex())
