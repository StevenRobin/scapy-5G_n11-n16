def imeisv_to_imei(imeisv: str) -> str:
    """
    将16位IMEISV转换为15位IMEI
    :param imeisv: 16位IMEISV字符串
    :return: 15位IMEI字符串
    """
    if not imeisv.isdigit() or len(imeisv) != 16:
        raise ValueError("请输入16位数字IMEISV")
    imei14 = imeisv[:14]

    # 计算Luhn校验位
    def luhn_checksum(number: str) -> int:
        sum_ = 0
        for i, digit in enumerate(reversed(number)):
            n = int(digit)
            if i % 2 == 0:
                n *= 2
                if n > 9:
                    n -= 9
            sum_ += n
        return (10 - (sum_ % 10)) % 10

    check_digit = luhn_checksum(imei14)
    return imei14 + str(check_digit)

if __name__ == "__main__":
    imeisv = input("请输入16位IMEISV：").strip()
    try:
        imei = imeisv_to_imei(imeisv)
        print("转换后的15位IMEI为:", imei)
    except Exception as e:
        print("错误：", e)