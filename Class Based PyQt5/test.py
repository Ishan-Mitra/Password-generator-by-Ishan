from requests import post

if __name__ == '__main__':
    resp = post("https://mitraelectronics.herokuapp.com/otp/verify/django/password-manager-by-ishan/root/6/otp/verify", {'email':'tushanmitra013@gmail.com','auth':'auth'})
    print(resp.text)

