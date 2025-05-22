def ToIMEI(IMEISV=''):
    sum_ = 0
    for i, digit in enumerate(int(x) for x in IMEISV[:-2]):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        sum_ += digit
    return IMEISV[:-2]+ str(sum_ *9 % 10)


>>> ToIMEI('1031014000012000')
'866222041877666'
