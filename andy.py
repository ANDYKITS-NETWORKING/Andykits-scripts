print("Hello, World!")

import sys
print(sys.version)

if 5 > 2 :
   print("okay")

x = 5
y = "Hello, World!"

print(x)
print(y)

#This is a comment.
print("This is Engineer Kitonga")

print("Hello World!")
print("Have a good day.")
print("Learning Python is fun!")

print('This is cool', end=' ')
print('and very easy')



def networking():
    ip = "172.168.16.1"
    port = 23
    connection = "The computer connects via ssh to " + ip + " port " + str(port)

    print(connection)

networking()

def networking():
    ip = '172.168.16.1'
    port = 23
    connection = 'The computer connects via ssh to ' + ip + ' on port ' + str(port)

    print(connection)

networking()

def conversion():
    x = 5

y = "John"

print(str(x) + ' ' + (y))
conversion()
#This is a conversion from int to string

c = 'sweet'

def sweetness():
    c = 'great'
    print('doing programming is ' + c)
    
    
sweetness()
  
print('doing programming is ' + c )

c = 'easy'

def sweetness():
    global c
    c = 'not tough'
  
    
    
sweetness()
  
print('doing programming is ' + c )


person = {
    "name": "John",
    "age": 25,
    "city": "Doha"
}

print(person)
# 'name','age','city' are keys
#'john','25','city' are values
#the above is a dict data type

person = {
    "name": "John",
    "age": 25
}

print(person["name"])

#in dict data type we use keys to get value

road={
    'makueni': 'nuu',
    'kitui': 45,
}
print(road['kitui'])

data = {
    "ip": "192.168.1.1",
    "port": 22,
    "connected": True
}


# above are dictionary data types


data = bytearray([65, 66, 67])
print(data)

# above is a bytearray data type

data = bytearray([65, 66, 67])

data[1] = 68

print(data)

# above is a bytearray data type and how to change a value

data = bytearray([9, 8, 7])
print(data)

data = bytearray([11, 8, 7])
data[2] = 6
print(data)
#used in networking too.. this is editable ,not just like the byte \t is an escape sequence for the tab character.

#The tab character has ASCII value 9.

#In bytearray, Python shows byte 9 as \t.




#Below is example of creating simple network packet using bytearray
packet = bytearray()

# Version byte
packet.append(1)

# Packet type
packet.append(2)

# Port number
packet.append(80)


#Below is how you modify packet data for the above (bytearrays are used in networking because :TCP,UDP & IP PROTOCOLS SEND RAW DATA)
packet = bytearray([1,2,80])

packet[2] = 22

print(packet)
#Bytes are from 0-255 , they represent binary data


def conversion():
    x = 1    # int
y = 2.8  # float
z = 1j   # complex




#convert from int to float:
a = float(1)

#convert from float to int:
b = int(2.8)

#convert from int to complex:
c = complex(1)

print(a)
print(b)
print(c)

print(type(a))
print(type(b))
print(type(c))

conversion()

import random

print(random.randrange(1, 10))
 
print("He is called 'Johnny'")
print('He is called "Johnny"')

a = "Hello, World!"
print(a[4])
#the above output is character o

#Check if "free" is present in the following text: below
ande = "The best things in life are free!"
print("free" in ande)

txt = "The best things in life are free!"
if "free" in txt:
  print("Yes, 'free' is present.")

#The output for the below is 'false' else it cld be 'true'
txt = "The best things in life are expensive free!"
print("expensive" not in txt)


txt = 'i love you'
print('you' in txt)

#To get the first character of txt in below
txt = 'hello world'
x = [0]

# Looping in python is used to check each character indipendently
for x in "banana":
  print(x) 

word = "address"
count = 0

for letter in word:
    if letter == "r":
        count += 1

print(count)

word = 'kitonga'
count = 0

for letter in word:
    if letter == 'k':
        count += 1

print(count)

l = 'kitonga'
print(l[3:5])


l = 'kitonga'
print(l[:2])

l = 'kitonga'
print(l[4:])

#below is negative indexing
b = "Hello, World!"
print(b[-5:-2])

r = 'james'
print(r.upper())

h = 'ANDY'
print(h.lower())

k = 'ANDY'
print(k.replace('N', 'T'))

a = "Hello"
b = "World"
c = a + " " + b
print(c)
#Above is concantination ,with a spacing 

d = 'ani' 
e = 'mal'
f = d + ' ' + e
print(f)


age = 36
txt = f"My name is John, and I am {age} "

print(txt)


# If x = 9, what is a correct syntax to print 'The price is 9.00 dollars'?
x = 9
print(f'The price is {x:.2f} dollars')
#f'...' creates an f-string (formatted string).
# {x:.2f} means:
# x → the variable value (9)
# .2f → format the number as a float with 2 decimal places.
price = 59
txt = f"The price is {price:.2f} dollars"
print(txt)

price = 78
print(f'The price is {price:.2f} dollars')

#Multiplication
txt = f"The price is {20 * 59} dollars"
print(txt)
#A backslash followed by an 'x' and a hex number represents a hex value:
txt = "\x48\x65\x6c\x6c\x6f"
print(txt) 
tuple1 = (1,2)
print(tuple1)
list1 =['mango','orange']
print(list1)

a = 70
b = 30
if a < b:
  
  print('This  great')

else: 
  print('This new')
  
def Kitonga() :
  return True

if Kitonga():
  print("YES!")
else:
  print("NO!")

  x = 200
print(isinstance(x, int))

sum1 = 100 + 50      # 150 (100 + 50)
sum2 = sum1 + 250    # 400 (150 + 250)
sum3 = sum2 + sum2   # 800 (400 + 400)
print(sum1)
print(sum2)
print(sum3)

#checking if a number is odd or even below, x is a variable, can be any number
x = 7
if x % 2 == 0:
    print("Even")
else:
    print("Odd")

    x = 16
if x % 2 == 0:
    print("Even")
else:
    print("Odd")


#Here’s how you can let a user input a number and then check if it’s even or odd: instead of harcoding
x = int(input("Enter a number: "))

if x % 2 == 0:
    print("Even")
else:
    print("Odd")


#Now our code can ask smeone to input data, what if they enter wrong values,this how to handle it
try:
    #x = int(input("Enter a number: "))
    
    if x % 2 == 0:
        print("Even")
    else:
        print("Odd")

except ValueError:
    print("Invalid input! Please enter a valid number.")
    # To have the sys continue asking till the right value is inputed

while True:

    #try:
        #x = int(input("Enter a number: "))
        
        if x % 2 == 0:
            print("Even")
        else:
            print("Odd")
        break

    #except ValueError:
        print("Invalid input! Try again.")

#while True:
#try:
        Musyi = int(input('Enter a number: '))
        if x % 2==0:
            print('Even')
        else:
            print('odd')
       # break
    #except ValueError:
        #print('This isnt correct! Try again')

#Special case where a number inputed is an integer or a float , NOTE:For negative , no problem
try:
    x = float(input("Enter a number: "))
    
    if x.is_integer():   # checks if it's a whole number
        x = int(x)
        
        if x % 2 == 0:
            print("Even")
        else:
            print("Odd")
    else:
        print("This is a float, not an integer.")

except ValueError:
    print("Invalid input!")


    #Below code (//) divides and rounds to nearest whole No:

x = 12
y = 5

print(x // y)

#A WALRUS Operator is shown below

numbers = [1, 2, 3, 4, 5,6]
if (count := len(numbers)) > 3:
    print(f"List has {count} elements")
# if we cld avoid walrus the above code cld look like this with #assign fst & #then check

numbers = [1, 2, 3, 4, 5] #checks no of items in the list

count = len(numbers)#assign first
if count > 3: #then check
    print(f"List has {count} elements")

    #example of using walrus to read a file line by line
    with open("james.py") as f:
     while (line := f.readline()) != "":
        print(line.strip())

#use walrus to avoid expensive calculation repeatition like network checks like below.
def kito_data():
    print("Fetching...")
    return 10

if (result := kito_data()) > 5:
    print(f"Result is {result}")

    #walrus used in working in regex; refer below
    import re

text = "My IP is 192.168.1.1"

if (match := re.search(r"\d+\.\d+\.\d+\.\d+", text)):
    print("Found IP:", match.group())
    #use walrus := to check interface status as below
    output = "GigabitEthernet0/0/1 is UP"

if (status := "UP" in output):
    print("Interface is up:", status)

    #use walrus in monitoring logs in networking
    with open("james.py") as f: #open the router.log file ,assign it to f
     while (line := f.readline()): #read the file line by line using walrus := operator
        if "ERROR" in line: #check error
            print("Alert:", line.strip()) #print alert if error found


#NOTE:= assigns value into a variable & returns at the same time/uses it in an operation immediately

#This operator checks if two variables are not equal !=


#is - Checks if both variables point to the same object in memory
#== - Checks if the values of both variables are equal
a = 0b110
b = 0b011

# 2 = 0010

print(a & b)


a = 0b110
b = 0b011

print(a ^ b)
# The ^ operator compares each bit and set it to 1 if only one is 1, otherwise it is set to 0
# 6 = 0110
# 3 = 0011
# --------
# 5 = 0101


Africa = ("Kenya", "Uganda","Togo")
(x,*y)=Africa
print(y)
# changing an item in a tuple, first convert into a list
games = ('soccer', 'valleyball','hockey')
t = list(games)
t[1]= 'tabletenis'
s = tuple(t)
print(s)

#there are two ways of addibng tuple into an existing tuple
#convert into a list
counties = ('kitui', 'makueni', 'machakos')
k=list(counties)
k.append('muranga')
counties=tuple(k)
print(counties)

computers=('dell', 'hp', 'toshiba')
y=('apple',)
computers +=y
print(computers)

#remove value in tuple
thistuple = ("apple", "banana", "cherry")
y = list(thistuple)
y.remove("apple")
thistuple = tuple(y)

print(thistuple)

#initiating a counter,with an increment of 1, as long as i to no of tuple is less
thistuple = ("apple", "banana", "cherry","mango", "juice","kall")
i = 0
while i < len(thistuple):
  print(thistuple[i])
  i = i + 1
#as above, whats abt increment of 2


thistuple = ("amaize", "banana", "cherry")

for i in range(len(thistuple)):
  print(thistuple[i])# items by referring to their index number:
  #Below code counts upwords
p = 1
while p < 9:

 print(p)
 p += 1
else:
 print('Mkate imeisha, hahaha')

#Counting and stoping
Bread = 1
while Bread < 9:
  print(Bread)
  if (Bread == 5):
    break
  Bread += 1



i = 0
while i < 6:
  i += 1
  if i == 3:
    continue
    print(i)

# Note that number 3 is missing in the result

# Create the i variable

# While loop: print 1-5, skip 3 with continue


i = 0
while i < 6:
  i += 1
  if i == 3:
    continue
    print(i)

#Testing if portforwading was done correctly using python nested loops code
#Make sure you dont test on your LAN hotspot yourself,,,,given is a public IP

#CHECKING IF THE PORT IS NOW OPEN USING CODE ON VSCODE (hotspot ur lapi)
import socket

# Target = client WAN IP
target = "197.248.30.21"

# Only port 8090
ports = [8090]

for port in ports:
    with socket.socket() as s:
        s.settimeout(2)  # 2 second timeout
        result = s.connect_ex((target, port))

        if result == 0:
            print(f"{target}:{port} OPEN ✅")
        else:
            print(f"{target}:{port} CLOSED ❌")


#converting to celcius from kelvin- below this without a function
            temp1 = 77
celsius1 = (temp1 - 32) * 5 / 9
print(celsius1)

temp2 = 95
celsius2 = (temp2 - 32) * 5 / 9
print(celsius2)

temp3 = 50
celsius3 = (temp3 - 32) * 5 / 9
print(celsius3)

#with a function no need to repeat a code
def fahrenheit_to_celsius(fahrenheit):
  return (fahrenheit - 32) * 5 / 9

print(fahrenheit_to_celsius(77))
print(fahrenheit_to_celsius(95))
print(fahrenheit_to_celsius(50))


def kelvin_to_celcius(farenheit):
   return(farenheit - 32)*5/9
print(fahrenheit_to_celsius(88))
print(fahrenheit_to_celsius(74))
print(fahrenheit_to_celsius(40))

#return value function code used in login systems, apps, websites greeting users.

def get_greeting(name):
    return f"Hello {name}, welcome!"

user_name = input("Enter your name: ")
message = get_greeting(user_name)
print(message)

#Time-based greeting (real-world logic)
def get_greeting(hour):
    if hour < 12:
        return "Good morning"
    elif hour < 18:
        return "Good afternoon"
    else:
        return "Good evening"

current_hour = 15
print(get_greeting(current_hour))

#Logging or system messages (networking relevance
def get_greeting(device_name):
    return f"Device {device_name} is reachable ✅"

router = "Router1"
print(get_greeting(router))


#return F ,,in pinging multiple devices
import os

def get_status_message(ip, status):
    if status == 0:
        return f"{ip} is reachable ✅"
    else:
        return f"{ip} is NOT reachable ❌"

def ping_device(ip):
    # -c 1 → send 1 ping (Linux/Ubuntu)
    response = os.system(f"ping -c 1 {ip}")
    return response

# List of devices (you can change these)
devices = ["8.8.8.8", "192.168.1.1", "10.0.0.1"]

for ip in devices:
    result = ping_device(ip)
    message = get_status_message(ip, result)
    print(message)

    #ping mullrtiple devices and port check

import socket

def check_port(ip, port):
    with socket.socket() as s:
        s.settimeout(2)
        result = s.connect_ex((ip, port))
        return result == 0

def get_port_message(ip, port, status):
    if status:
        return f"{ip}:{port} OPEN ✅"
    else:
        return f"{ip}:{port} CLOSED ❌"

target = "8.8.8.8"
ports = [53, 80, 443]

for port in ports:
    status = check_port(target, port)
    print(get_port_message(target, port, status))


    import socket

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a website (e.g., Google) on port 80 (HTTP)
s.connect(("://google.com", 80))

print("Successfully connected!")
s.close()



