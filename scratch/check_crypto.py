try:
    from Cryptodome.Hash import SHA256
    print("Import Cryptodome successful")
except ImportError:
    try:
        from Crypto.Hash import SHA256
        print("Import Crypto successful")
    except ImportError:
        print("Both Cryptodome and Crypto failed")
