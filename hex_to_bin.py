with open("./digest.txt", "wb") as f:
    digest = bytes.fromhex("f4090da264cfb4ad92b06801a5ee9ff5196e14501b22cff19818331129108abfc0f17376c948d2357e1999a33b096b6a5f64e81d33aba715287999c5752b0451cc628ed6e882b306c3206a95579f2d4c")
    f.write(digest)
