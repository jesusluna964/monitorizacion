import mysql.connector
import datetime
hora = datetime.datetime.now()
mydb = mysql.connector.connect(
  host="172.18.0.3",
  user="luna",
  passwd="12345",
  database="monitoreo"
)

mycursor = mydb.cursor()

sql = "INSERT INTO monitoreoAppl_adminglobal (usuario, password, token, horaToken, chatID) VALUES (%s,%s,%s,%s,%s)"
val = ('luna', '$6$I+NBPWlL+5dd3w==$oltj/Dv7SOZtJzDnYL0GvW49ikYtgAlrIQrk8fYyw9xCOXdb/WfTibqcQo5nYgBsZ9zccuOKZV5rORadkXaG/0', 'NULL', hora, '@torkeenks')
mycursor.execute(sql, val)
mydb.commit()
