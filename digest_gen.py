def start(content: bytes):
    with open("./digest.txt", "wb") as f:
        print(content.hex())
        print(len(content))
        f.write(content)

start(b"\x70\x69\x6e\x67")
