---
title: "[BreizhCTF 2023] - Série Yakuza "
slug: serie-yakuza
date: 2023-03-19T22:00:53+01:00
tags: ["OSINT", "BZHCTF"]
draft: false
---

## Introduction

Lors du BreizhCTF 2023 qui s’est déroulé du 17/03/2023 au 18/03/2023, j’ai eu l’opportunité de réaliser une partie des challenges d’OSINT. Etant moi-même joueur de CTF et grand amateur d’OSINT, j’avais pour idée de réaliser une série de challenges réaliste, chose que l’on voit rarement en CTF. L’objectif derrière celle-ci est de plonger le joueur dans une véritable enquête. Rapidement, le joueur se retrouve submergé par un flow d’informations et c’est à lui d’en faire le tri, conjointement avec l’énoncé qui sert à le guider. Plusieurs composantes essentielles ont été nécessaires quant à l’élaboration de ces challenges :

- le thème et la langue associée (japonais),
- l’intervention d’acteurs réels,
- l’utilisation de comptes véritables.

Cette série est composée de 5 challenges mélant plusieurs techniques d’OSINT : SOCMINT, GEOINT et investigation physique. La finalité est de retrouver et tracer un attaquant, membre d’un groupe criminel japonais ayant pour objectif de rencontrer un contact à lui en France lors du BreizhCTF. Tout au long de ces challenges, le joueur est amené à récolter différentes preuves qui seront utiles pour incriminer l’homme en question.

---

## Yakuza (1/5) - Nihon he yōkoso

### Enoncé 

![](gifs/cat-bowl.gif)

*Oh tiens, je viens de recevoir un message. À cette heure-là ? Sur mon tél pro ? C’est étrange. Il faut que je l’ouvre sans plus tarder. Moi qui pensais pouvoir me détendre au BreizhCTF avec une bonne galette saucisse, me voilà de nouveau sur une enquête…*

*“Bonsoir Conan,*

*J’espère que votre séjour à Rennes se passe pour le mieux. Malheureusement, nous devons l’interrompre. Nous vous sollicitons exceptionnellement cette nuit dans le cadre de la mission d’investigation YKZ_001. Comme vous le savez, nous traquions il y a plusieurs mois un groupe de yakuzas suite à la compromission de nature lucrative d’un OIV. Cependant, ils n’ont laissé presque aucune trace depuis ce jour.*

*Ce n’est qu’il y a quelques minutes que nous avons intercepté un message du groupe à propos de leur prochaine attaque. Par chance, il contient une signature. Celle-ci se compose d’une suite de caractères en japonais : “土方剛史”.*

*Nous sommes certains qu’avec cette information, vous serez à même de retrouver l’un des acteurs de ce groupe.*

*Nous comptons sur votre expertise pour mener à bien cette enquête. N’oubliez pas que chaque détail compte. Collectez, notez et recoupez les informations, c’est essentiel à la réussite de toute mission. Vous ne disposez que de quelques heures pour retrouver l’individu et aider à découvrir leur prochaine cible.*

*Bonne chance.”*

### Détails du challenge

| Event          | Serie  |       Challenge     | Category | Points | Solves |
|----------------|--------|---------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza |Nihon he yōkoso (1/5)| OSINT    | N/C        | N/C    |

### TL;DR
1. Traduction de la signature en rōmaji : `土方剛史` => *Takeshi Hijikata*
2. Recherche du nom sur Twitter -> Compte [@HijikataTakeshi](https://twitter.com/HijikataTakeshi/)
3. Dans un tweet, la cible parle d'un groupe dans lequel il serait plus actif. Il se trouverait sur un réseau social très populaire au Japon
4. Recherche des réseaux sociaux japonais populaire => **LINE** est le n°1
5. Recherche d'utilisateur sur LINE avec le même nom d'utilisateur que celui sur Twitter (marche aussi avec son prénom + nom) => On trouve son compte
6. En bannière, il y a une URL permettant de rejoindre un groupe LINE
7. En le rejoignant, présence du flag dans la partie "Notes" du groupe. 

### Objectif
L'objectif de ce premier challenge est de faire le lien entre la signature du message et une vraie personne. De ce fait, il faut trouver des traces de la cible sur Internet.  

### Méthodologie
Pour ce faire, il faut commencer par partir de cette fameuse signature : `土方剛史`. À moins d'avoir le JLPT et de comprendre directement sa signification, il faut commencer par la traduire. Pour ce faire, nous pouvons utiliser **DeepL**.

![](traduction-signature.png)

Nous nous retrouvons donc avec un prénom et un nom : `Takeshi Hijikata.` En faisant une recherche de celui-ci sur Twitter, nous pouvons trouver son compte. 

![](compte-twitter.png)

Après investigation sur son compte, deux tweet se trouvent être particulièrement intéressants :

![](tweet-1.png)
![](tweet-2.png)

La cible nous dit d'elle même qu'il se trouve être plus actif sur un autre réseau social. Celui-ci serait le plus populaire au Japon. Après une recherche internet plutôt basique, on tombe rapidement sur `LINE`

![](popular-sn.png)

En cherchant le nom d'utilisateur sur LINE, on tombe sur son compte :

![](compte-line.png)

Nous remarquons qu'en bannière de son compte se trouve un lien. Celui-ci permet de rejoindre son groupe LINE. Il faut noter qu'afin de rejoindre un groupe, il faut disposer de l'application mobile.  

![](compte-line-2.png)

Une fois sur le groupe, nous nous dirigeons dans les notes dans lesquelles plusieurs informations s'y trouvent, dont notre flag qui marque la fin de ce premier challenge.

![](flag.png)

### Flag

`BZHCTF{L1N3_1s_v3ry_f4m0us_1n_J4p4n}`

---

## Yakuza (2/5) - Tebori

### Détails du challenge

| Event          |  Serie  | Challenge     | Category | Points | Solves |
|----------------|---------|---------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Tebori (2/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. Note sur un magasin de tatouage + photo d'un `Kamon Tomoe`
2. Recherche "most famous tattoo shop in japan" => Tokyo Three Tides Tattoo
3. Le logo du magasin est un `Kamon Tomoe` => confirmation du magasin
4. Il y en a 2 au Japon (Osaka et Tokyo). Grâce aux photos sur le groupe LINE, on sait qu'il se trouve à Osaka. 
5. Filtrer par commentaire le plus récent pour obtenir le flag.

### Objectif
L'objectif de ce second challenge est maintenant de faire le lien entre la cible et le groupe de Yakuza. Il faut obtenir une preuve de son appartenance. 

### Méthodologie

Comme le souligne l'énoncé de ce deuxième challenge, il y a la présence de deux message sur le groupe LINE à propos d'un salon de tatouage et du tatouage en lui-même. Dans ceux-ci, notre cible dit qu'elle aurait fait un tatouage comme le veut la tradition dans un magasin ayant pour enseigne un *"Kamon Tomoe"*. 

![](post-line.png)

Le tatouage en question :

![](post-line-2.png)

Il faut donc commencer par rechercher les magasins de tatouages au Japon. Pour ce faire, une piste intéressante est de commencer par les magasins les plus connus. 

![](famous-tattoo-shop.png)

On tombe assez rapidement, voire immédiatement, sur "Tokyo Three Tides". En effectuant des recherches sur cette enseigne, on tombe sur le logo du magasin : 

![](logo-tattoo.png)

Le logo se trouve être une sorte de *Kamon Tomoe*, nous indiquant que l'on est sur la bonne piste. En considérant que la cible s'y est fait tatouée, il a potentiellement laissé un avis ou une photo. Il reste à déterminer lequel des deux magasins à Tokyo ou Osaka est le bon. Avec une légère corrélation d'information et un peu de GEOINT sur les photos présentes sur LINE ou Twitter, on peut en déduire qu'il se trouve très souvent à Osaka. EN voici un exemple :

![](exemple-osaka.png)

Regardons les avis de [Tokyo Three Tides Osaka](https://www.google.com/search?client=firefox-b-d&q=tokyo+three+tides+osaka#lrd=0x6000e70e351eebd3:0x5cfbe83df2d33f5b,1,,,,). En triant par photo les plus récente, on tombe sur un commentaire de Hijikata Takeshi.

![](avis.png)

Il contient d'ailleurs une image sur laquelle le flag est écrit.

![](flag.png)

### Flag
`BZHCTF{t4tt00s_4r3_p4rt_0f_th3_tr4d1t10n}`



