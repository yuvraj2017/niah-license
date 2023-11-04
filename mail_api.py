import psycopg2
import json



def get_niah_id_data(niah_id):
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        for data in dailyData:
            if data.get("niah_id") == niah_id:
                return data


def get_eco_prod_data(ecosystem_product):
    ecosystem, product = ecosystem_product.split('/')
    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        for data in dailyData:
            if data.get("type") == "language":
                ecosystem = data.get("language")
            if data.get("type") == "platform":
                ecosystem = data.get("type_name")
            package = data.get("package")
            if ecosystem == ecosystem and package == product:
                return data


conn = psycopg2.connect(user="versa",password="versa123",host="127.0.0.1",port="5432",database="niahdb")
cursor = conn.cursor()

query  = "select user_id from license_master_db"
cursor.execute(query)

user_list = [row[0] for row in cursor.fetchall()]

update_report = []

for user_id in user_list:

    query = "select emailid from license_master_db where user_id='%s'" % user_id
    cursor.execute(query)
    recipient = cursor.fetchone()[0]

    query = "select data from subscribe_tab where user_id='%s'" % user_id
    cursor.execute(query)
    userData = cursor.fetchall();
    niah_id_list = []
    product_list = []

    for uData in userData:
        data = uData[0]
        if 'niah_id' in data:
            niah_id_list.append(data['niah_id'])
        if 'product' in data and 'ecosystem' in data:
            product_list.append(f"{data['ecosystem']}/{data['product']}")


    niah_id_list = list(set(niah_id_list))
    product_list = list(set(product_list))


    niah_id_update = []
    product_update = []

    with open('/var/DB/feeds/updates/1_day.json', 'r') as update:
        dailyData = json.load(update)
        niah_id_data = {}
        for data in dailyData:
            niah_id = data.get("niah_id")
            if niah_id in niah_id_list:
                niah_id_update.append(niah_id)
            
            
        for data in dailyData:

            if data.get("type") == "language":
                language = data.get("language")
            if data.get("type") == "platform":
                language = data.get("type_name")
            package = data.get("package")

            if language and package:
                for ecosystem_product in product_list:
                    ecosystem, product = ecosystem_product.split('/')
                    if ecosystem == language and product == package:
                        product_update.append(ecosystem_product)
                         

    if len(niah_id_update) > 0 or len(product_update) > 0:

        if len(niah_id_update) > 0:
            niah_id_data = get_niah_id_data(niah_id)
        if len(product_update) > 0:
            eco_prod_data = get_eco_prod_data(ecosystem_product)


        res = {}
        res["receiver"] = recipient
        res["niah_updates"] = niah_id_data
        res["eco_prod_updates"] = eco_prod_data 

        update_report.append(res)

with open("update_report.json", "w") as outfile:
    json.dump(update_report, outfile, indent=2)

# print(update_report)