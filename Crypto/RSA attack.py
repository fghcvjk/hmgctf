from gmpy2 import *
from Crypto.Util.number import *
import sympy
import random
from secret import flag

p1 = getPrime(1024)
print(p1)
#p1=172071201093945294154292240631809733545154559633386758234063824053438835958515543354911249971174172649606257936857627547311760174511316984409767738981247877005802155796623587461774104951797122995266217334158736848307655543970322950339988489801672160058805422153816950022590644650247595501280192205506649936031

p2 = p1 - random(999,99999)
print(p2)
#p2=172071201093945294154292240631809733545154559633386758234063824053438835958515543354911249971174172649606257936857627547311760174511316984409767738981247877005802155796623587461774104951797122995266217334158736848307655543970322950339988489801672160058805422153816950022590644650247595501280192205506649902034

p_1=1
for i in range(1,p1+1):
    p_1*=i
p3 = sympy.nextPrime(p_1 % p2 )

p4 = p3 >> 50 << 50
p = p4
while(isPrime(P)!=1):
    P = p + random.randint(0,2**50)

Q = getPrime(1024)

e = 1+1+1
N = P * Q
print(N)
#N=28592245028568852124815768977111125874262599260058745599820769758676575163359612268623240652811172009403854869932602124987089815595007954065785558682294503755479266935877152343298248656222514238984548734114192436817346633473367019138600818158715715935132231386478333980631609437639665255977026081124468935510279104246449817606049991764744352123119281766258347177186790624246492739368005511017524914036614317783472537220720739454744527197507751921840839876863945184171493740832516867733853656800209669179467244407710022070593053034488226101034106881990117738617496520445046561073310892360430531295027470929927226907793

flag=bytes_to_long(flag)
c = pow(flag,e,N)
print(c)
#c=15839981826831548396886036749682663273035548220969819480071392201237477433920362840542848967952612687163860026284987497137578272157113399130705412843449686711908583139117413
