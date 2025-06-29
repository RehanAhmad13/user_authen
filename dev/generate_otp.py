# dev/generate_otp.py
import pyotp
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_otp.py <TOTP_SECRET>")
        print("Example: python generate_otp.py JBSWY3DPEHPK3PXP")
        return

    secret = sys.argv[1]
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    print(f"\n OTP for secret [{secret}]: {otp}\n")

if __name__ == "__main__":
    main()
