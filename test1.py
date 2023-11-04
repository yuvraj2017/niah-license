
import json


# EMAIL_ADDRESS = 'yuvipatel1727@gmail.com'
# EMAIL_PASSWORD = '17YuvRaj@2018'
niah_id = ''
def get_niah_id_data(niah_id):
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        print(dailyData)
        for data in dailyData:
            if data.get("niah_id") == niah_id:
                return data


ecosystem_product = 'debian/perl'
def get_eco_prod_data(ecosystem_product):
    ecosystem,product = ecosystem_product.split('/')
    print(product)
    print(ecosystem)
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        print(dailyData)
        for data in dailyData:
            language = data.get("language")
            package = data.get("package")
            if language == ecosystem and package == product:
                return data
            
yash = get_eco_prod_data('debian/perl')
print(yash)