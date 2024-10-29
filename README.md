# ripemd160-attack

A simple CLI application that executes preimage search and birthdays attack on a part of RIPEMD-160 hash.

## Usage

First argument specifies the attack type:
* `preimage` - preimage search attack
* `birthdays` - birthdays attack

Second argument specifies the way of creating new messages from the original one:
* `1` or `random_number` - create new messages by appending a random number to the original message
* `2` or `transform` - create new messages by randomly transforming the original message
* `3` or `number_in_sequence` - create new messages by appending constantly increasing natural numbers to the original message

## Examples

```console
$ ripemd160-attack preimage 1
Initialising preimage search attack...
Some huge message	b97daf32bb5e4ac20c34d815f5cdb164d85259d9

Searching for a preimage...
1	Some huge message2454588525	2c314a2b0104553f850ec815bd8c5609ba1770d7
2	Some huge message527489877	f4cb7bb9f0f8c303e84e75d092de818d57ac5b46
3	Some huge message433503927	9390dbf92380541c89e9ad1c7134a366fa59eaf9
4	Some huge message3743163627	eab46f9dbcc1692984bb030756cb0c50dd9ea1bb
5	Some huge message913513352	0f3ff5eaec89bcdafd144611ea3b83c1fd8c3135
6	Some huge message50757231	7b18fbe60d83d8e4b4842cdf1a1f7ac1fe422ef0
7	Some huge message3190530052	13003342dfd222ec34b590592d779b4d8b46869d
8	Some huge message4069452196	40acfad171284be8b5b2f4d684b7a75bf72d21a0
9	Some huge message3710137110	f74dd3441f8aab0932de65ab968f40373eb6ea82
10	Some huge message1193702995	09c2ebfea85deeccefbbcf086bbbc35b0f2de873
11	Some huge message3945116401	9cf1cb9d9ed9902989ce56b19bf8d53b7291b67a
12	Some huge message223118778	612e0b72d6c77f231c9af8eb2a193b29ca915ea8
13	Some huge message140209468	cbf25f6307f052e718995d2f3b7e84b8944bfa98
14	Some huge message148571796	cb67a474ece5c9e80733783514e80567ecb6cb08
15	Some huge message2771958398	51043e0c3703948985bffe21072279698479bf12
16	Some huge message2704657532	2e2c67e9dd6f573ba2678a4c6b828f3e6838b89f
17	Some huge message4234223599	89e931917c071231c00c007a512be806fe26a984
18	Some huge message35372765	656ee1213cb4f67b20d464c5b1182a73b06b2491
19	Some huge message3191634050	594caaa2f9ee2579a1ed199c75ba52399757eb67
20	Some huge message1087069405	0ad1932f3eeabdea95e5446dc9f7ff7a785a4b31
21	Some huge message3354467150	39c8a1de12c171cb1918d726424b6dc15041e524
22	Some huge message1213528819	f84a484f16ad6e2cb45e505388d9f785d3b53cae
23	Some huge message2402207541	8117bd9233a5ffbfc81a24656cbe99685a5b360b
24	Some huge message497385166	a1b29abb02c360afebf9c68e88f304a82866e38e
25	Some huge message173627261	78507b40ef8cf6b2d1f1b6a2a7ce7630dbde9236
26	Some huge message4086930645	da37ac7cfd1dc5995915ebfa1897c290c7a10c52
27	Some huge message2136394148	bc548bfa3a5bb6660043c1b2fec8ae5131cedf3d
28	Some huge message347497496	00721f02bf982c6f1a25651f4f0f27d49ed8f2ba
29	Some huge message2067602131	e7820bbcd0024f5e388f4d33d073051a2fac5403
30	Some huge message2699021612	fa5d423f301f3d54644490f27e41a09ed684258c
...

[SUCCESS] Found preimage on iteration 148595!
Some huge message	b97daf32bb5e4ac20c34d815f5cdb164d85259d9
Some huge message3823275353	31327e08e01cdb53e896b082c9a59ca4cc1259d9

[TIME] Attack took 1.25s
```

```console
$ ripemd160-attack preimage 2
Initialising preimage search attack...
Some huge message	b97daf32bb5e4ac20c34d815f5cdb164d85259d9

Searching for a preimage...
1	Sr*e *U** m**#p*a	58074910a2648140c2921df09de7f113061a8cd0
2	So** HdGl*m<ss55E	15e1ef553262500982bf1256e548ed8b387f1b8f
3	tOMe *SGE**F<s**e	86c34d3c9036de081f08f9cb53ba89a5cb7a44a7
4	*oMEmh3g*PQ*O*ARe	ddd5d6049357d1de8455a8b411418e67f95e0da4
5	6L*e6**G@ meLOaGE	e6c2f08eb97b9248b7276224e5813c933d04e076
6	zO*| H*gC4*e;s*gX	0d5abaacb070378be15adc15a9851e61098443a7
7	*oMe$HuF*FM*Ssc*e	dd52e7b266f609fcc12b208ee484c68b76550517
8	**E***UU**me**hg*	3be8947df27bd6e11e44f944b8c12e684cbeb28a
9	s*M} .*g* Me*SA**	92fd0f97355ade2c81d55cae95968ad6c7fedf1f
10	*InE Hug9 i*S****	2bb712e36347d0b9dd51cc9aba69269e43f1f9de
11	sOME4hu*n71*s6Agr	a245b9726d6dd82b008f901fa47dc5cb49e51ee9
12	sOML *U[E mER*aG*	ccd902e62f2d0c5fdaa07a5d01059f1df44fccf6
13	sHmE^<UG*G*E*SaGW	05767479c738e07e9f0ae497583d50d3346626e7
14	TOMetM*** m**sO**	2ab6fc2bde265331572196bf24561657b1a276ac
15	*O*e cUg*pM[sSAGg	d8e020eb487d4c4c8965da6589bfa297ee12a904
16	SWM***|g**Mb*Sa.o	f314270ec9d3c3be5f7bfacbbfd991733723b9e2
17	SOm*0{U<d*XeSsAGE	4e1145c5c0908fe5ea18bd8ca8553aa12ad26744
18	S*Me*hu*e**ESsaG2	9385f43002a0a3aa8db0daf4382bad39ca2821d4
19	*_me*~U*Z *ESSagE	6fdb40c0a37d195cbc067ba5ee43ec7fe09094c6
20	*tMeD%uGE }E**a/E	4e1aba8a5d7792b2c375a0275a7e3cac9054dc79
21	S*mu*Z**E h!Ssa*e	28f821b3754d4fab4fc5f5a5ba40fbf550392e9a
22	**0E0H#NeZ9e**0**	6f11e87349e3ddde71274249c2afedf1c9863d06
23	S.** Nuge*MHSSagE	bc6ce1c1bc6f085b324cb40fbfd8aea0a1a96413
24	*OZ [hU*E meSs*g*	6071037eddd30b13990b130baf8a3a4abf5011ac
25	som]XHU****es**G*	f815625f664adb39428af5d8e5bd2ae851a96290
26	sO*E*=up**me(sAgG	b1243caaa83c65a1242fad3b4848c942549b5ead
27	so*e*h**EfMES*Y#2	cca1c476b793f43bbcb8cdfd6b7a76a452625a56
28	soMe H9Ge MjSSAge	3a35bc2e7b5748ddf6fbed011548589eae1961c8
29	SwmE**Ug* ME s*GE	237fc9a532f9b16bb5e0c94471d00e68ceabdbd7
30	*oMe}*[** *e*****	e5b890fc9c900ab9b010dc39df68b36dfad3f56d
...

[SUCCESS] Found preimage on iteration 3018!
Some huge message	b97daf32bb5e4ac20c34d815f5cdb164d85259d9
SrM*v***I *ES*aGE	caf565609c6886ecce3ad61caec3d106ed2d59d9

[TIME] Attack took 174.56ms
```

```console
$ ripemd160-attack birthdays random_number
Initialising birthday attack...
Another big message	fd73e48a174bc301c89f53341e332ade0cc104ac

Searching for a collision...
1	Another big message713552114	4c2401722cc330b396e6eeaf748f34849bf56e13
2	Another big message4041935161	1d0251e2f37028919b7c24b3d6c833bc0bf409ec
3	Another big message1601592110	b25e805e2f9115d8c215ac730d779dddcaf80507
4	Another big message147677542	3cd472a45016ef40b48726413fe312133ea5157a
5	Another big message715816746	da999b89cbd54bc895f30a68c7986c5b59b76f4c
6	Another big message3354044877	fd3268561fe730e08bd373694966909f2215bb55
7	Another big message2390903854	5216244862e3bcbc6993acb91b6aca932fba2d21
8	Another big message2429550212	41a8ea520ea5c87b6003e4f3832981e934c00c54
9	Another big message956949215	da2eeb9b218e9473b5684307f65ed52254471968
10	Another big message33081732	2784306664b7f8b92425708f7537111f706f7b6c
11	Another big message1868846516	095797c396939fae795a23241f4108875b8e45be
12	Another big message4246772227	1f3d94bb4d94eaf885970b6b39b64df451b9fdf8
13	Another big message3515377217	35ebade8a810b710436ba89c7c35b2bffed953e5
14	Another big message75109665	c9ac4490c0696161e6ad837bba1bb812291ca55d
15	Another big message2594735945	f6e375f442b474d4a250cc5968902f9fe2a80763
16	Another big message20001931	810ec9dd37349aaa271d4d30b6bc1394b5c981da
17	Another big message141050664	6ec4c85302fe4b8a439c5d75b1443e7398156196
18	Another big message1375538347	94d82cf73b7a1740f15bf736deaff1d5efb6f5d2
19	Another big message196010122	d7081898dc593576696103d3bbfcb73a7e5fa30b
20	Another big message4221493155	0668af281485e55bbc1fa34328c99bc94e3429a4
21	Another big message3218978704	b66292f6f9a487b3cf1aa3e1f99c5e532e768b70
22	Another big message2327091240	7e701d42a413cdeb5573722f7b16493af769a8c9
23	Another big message1004215020	a8e1e0c3f17ad40de54096f6b12812662abae384
24	Another big message2103381646	e1dd8a169f1ea4799b6a0b42c73679c4fba9d36b
25	Another big message1961337920	0b7ba630cf08637ca3f2bc1ee4e0da9df0cfc8cf
26	Another big message1719786203	1c3abaf3304799b5cac49ad29e74f74799b37d51
27	Another big message2226289022	18f6dd5e96b9cfc0672129647d7f11f90a06f5ae
28	Another big message1922390648	6da4b899d86fafb46d2e231cb3ef7d02ef400958
29	Another big message874074526	e8a4550f4cdca0f7a7a76f73c48d04049319c2d2
30	Another big message251069761	b867dfa88f6b5284571931121c39078b095b81a6
...

[SUCCESS] Found collision in iteration 18981-3990!
Another big message3034485325	d11cd1ba566439d6eda7f6ccad67fd0de26ecc9f
Another big message1382019924	d074a56c9101ee8b57862415a03e5c2ce26ecc9f

[TIME] Attack took 23.67s
```

```console
$ ripemd160-attack birthdays transform
Initialising birthday attack...
Another big message	fd73e48a174bc301c89f53341e332ade0cc104ac

Searching for a collision...
1	an**[**w*i?kM*(Fa9E	3b216ecea36cdd1a2f4021e4ba4e1d224162d7ce
2	FN*pHER*}IS*m*Sd**#	5f1b79ffffcb2410d1944eac65a965a802fab0d1
3	**O***R big *E@*A*E	9dd69dbcc7efde7935c55cc85b70712e7842b5fd
4	aNoThER}Bi)*_F*****	0b5380b386c9a920a4598cae41b88f77269f16aa
5	3No95*r*B4* Me*s*Ge	a76aed88e09be034e3fa29392d18d3f4c5b7a450
6	2**THEJ*b*"*|EGS1G*	5d110303562f2e116efe499a1559bb5cfbb4d079
7	/*o*****bIa RjsSaGe	e9e8da63487409a8f8f4ae5ebddffa247bc0b8e6
8	A~oeHeR*bI* mE*S*I&	624f8fa4ebfb37dee3fcc996ce622cc25df91f48
9	A**TheRa#5* &ESYAtK	479abde9e3025ebb058df9288ec726329e298bae
10	**othef***>*ME*,hG*	fa9f3418acb870b3a5e774b68fef04ccc9ba8017
11	Ag*Q*E<*Bin m*'sap}	461ee28955433b7fc1072fa26bf06544be8499de
12	+n TZXRkb$G ***S*ge	10c75948dde828d44a4a8079e2968fe9e6c2a13a
13	7*O*heZfb*g*MESS*;Z	2d5d4eeb39c3ea567d4ce86bda6da9b1031e124e
14	**OT}EGabIG DLSSa*E	bf9145f5ecc9fb1392f5db92ccc794156a54ecf4
15	AnOT*ER **g *EaSXg*	30a13c676fc3159faee22a85ac91e91170b4b044
16	A*O/hW**Bb* *ts!*gE	132362bd39a9b2eeea5b8e73c0f5704a92ef4e52
17	Ano*H*r -*G m*}sAn{	e4ee6ef4f6233c7da5dd83e6e61ddc7640a7e0fa
18	Ano***N*bka meSs;gE	13e2743ca483bcd8fc154a69428341b9004da4ee
19	KNO+H*r ciG2mA]*AgE	99b84e18de5981de6a4700f4a66d236d44e2cbfc
20	****h***K*Y$*D1sa*6	a0567b09d38c5baf19da3c6935e09e6d30ea54fa
21	A~*t*ex BIW*M.SsAgE	207d26286ba8e5f3798abd3557c707341f13d2f7
22	aNoTHER*bI**mG%sZGE	564b5623bc25f0b06c3c3ebe8c5c71462cb47bff
23	@NvtcEr*L*G)BSs7PA*	a829d78dd4eb87666908e8862ea53a9b90a23a75
24	R[#*beL A*G vES/aQ[	6d58dbc015b1adae905ce69ee9559123d648907e
25	A**T[TR_*If'MEvSa**	640b7cc3307f454633abc19d64316de027eb5912
26	*N**HER biG m4*S**E	d3a50cff554a63f969a20b58466fb0722756cac4
27	An*3H*( b****ESSA*e	c87a56a38297fccd3258f7135a6391e25f720e0d
28	A*O*h 6V*:* jnBs*VQ	b5c1f168fd49afac2fc032af602177a5b87b0246
29	aJ:*h*r*BiG mESsAgE	c0d331bad45bdfef6b3ae21e7670c3fdbb182c6c
30	0n*H*e9 !*w *EW*Ag*	1416da93283c235303ac5a8c5d66544eae94dd40
...

[SUCCESS] Found collision in iteration 65724-45702!
A*Ot\"R**iG]OEsS*|*	af854829957262f164c46a1f69c1e887c04e95c8
A*OT**r bis Mes!1G*	fc026fd3bc897aba2ab8714b02bd44fcc04e95c8

[TIME] Attack took 282.17s
```

## Extra

Python 3 script `to_table.py` is also added to the project for converting obtained data into a LaTeX or text table with 2 columns:
1. Attack number (`att`)
2. Iteration count (`iter`) - number of iterations during the attack

It accepts path to directory with output files and the type of a table to create.
