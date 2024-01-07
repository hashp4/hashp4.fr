---
title: '[BreizhCTF 2023] - Série Yakuza'
date: 2023-03-19T22:00:53+01:00
lastmod: 2023-03-19T22:00:53+01:00
draft: false
authors: ["hashp4"]
description: "Solution des challenges d'OSINT que j'ai eu l'occasion de créer pour le BreizhCTF 2023."
summary: "Solution des challenges d'OSINT que j'ai eu l'occasion de créer pour le BreizhCTF 2023."
featuredImage: "feature.png"

tags: ["OSINT", "BreizhCTF", "SOCMINT", "GEOINT", "irl"]

categories: ["Writeup"]
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

```
Oh tiens, je viens de recevoir un message. À cette heure-là ? Sur mon tél pro ? C’est étrange. Il faut que je l’ouvre sans plus tarder. Moi qui pensais pouvoir me détendre au BreizhCTF avec une bonne galette saucisse, me voilà de nouveau sur une enquête…

“Bonsoir Conan,

J’espère que votre séjour à Rennes se passe pour le mieux. Malheureusement, nous devons l’interrompre. Nous vous sollicitons exceptionnellement cette nuit dans le cadre de la mission d’investigation YKZ_001. Comme vous le savez, nous traquions il y a plusieurs mois un groupe de yakuzas suite à la compromission de nature lucrative d’un OIV. Cependant, ils n’ont laissé presque aucune trace depuis ce jour.

Ce n’est qu’il y a quelques minutes que nous avons intercepté un message du groupe à propos de leur prochaine attaque. Par chance, il contient une signature. Celle-ci se compose d’une suite de caractères en japonais : “土方剛史”.

Nous sommes certains qu’avec cette information, vous serez à même de retrouver l’un des acteurs de ce groupe.

Nous comptons sur votre expertise pour mener à bien cette enquête. N’oubliez pas que chaque détail compte. Collectez, notez et recoupez les informations, c’est essentiel à la réussite de toute mission. Vous ne disposez que de quelques heures pour retrouver l’individu et aider à découvrir leur prochaine cible.

Bonne chance.”
```

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

![](1/traduction-signature.png)

Nous nous retrouvons donc avec un prénom et un nom : `Takeshi Hijikata.` En faisant une recherche de celui-ci sur Twitter, nous pouvons trouver son compte. 

![](1/compte-twitter.png)

Après investigation sur son compte, deux tweet se trouvent être particulièrement intéressants :

![](1/tweet-1.png)
![](1/tweet-2.png)

La cible nous dit d'elle même qu'il se trouve être plus actif sur un autre réseau social. Celui-ci serait le plus populaire au Japon. Après une recherche internet plutôt basique, on tombe rapidement sur `LINE`

![](1/popular-sn.png)

En cherchant le nom d'utilisateur sur LINE, on tombe sur son compte :

![](1/compte-line.png)

Nous remarquons qu'en bannière de son compte se trouve un lien. Celui-ci permet de rejoindre son groupe LINE. Il faut noter qu'afin de rejoindre un groupe, il faut disposer de l'application mobile.  

![](1/compte-line-2.png)

Une fois sur le groupe, nous nous dirigeons dans les notes dans lesquelles plusieurs informations s'y trouvent, dont notre flag qui marque la fin de ce premier challenge.

![](1/flag.png)

### Flag

`BZHCTF{L1N3_1s_v3ry_f4m0us_1n_J4p4n}`

---

## Yakuza (2/5) - Tebori

### Enoncé

![](gifs/swag-cat-swagger.gif)

```
Parfait, j’ai réussi à retrouver l’individu en question et à rejoindre son groupe d’amis. Le moins qu’on puisse dire, c’est que c’est une vraie mine d’or en terme d’informations. Cependant, rien ne le rattache à ce groupe de yakuza… Mais une note m’interpelle tout de même. Dans celle-ci, il parle visiblement d’un magasin de tatouages et de “Kamon Tomoe”.

Je sens qu’il y a quelque chose à creuser de ce côté-là.

En-tout-cas, il faut que je continue avant qu’il ne remarque quelque chose. Il a l’air très actif sur ce groupe de discussion.
```

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

![](2/post-line.png)

Le tatouage en question :

![](2/post-line-2.png)

Il faut donc commencer par rechercher les magasins de tatouages au Japon. Pour ce faire, une piste intéressante est de commencer par les magasins les plus connus. 

![](2/famous-tattoo-shop.png)

On tombe assez rapidement, voire immédiatement, sur "Tokyo Three Tides". En effectuant des recherches sur cette enseigne, on tombe sur le logo du magasin : 

![](2/logo-tattoo.png)

Le logo se trouve être une sorte de *Kamon Tomoe*, nous indiquant que l'on est sur la bonne piste. En considérant que la cible s'y est fait tatouée, il a potentiellement laissé un avis ou une photo. Il reste à déterminer lequel des deux magasins à Tokyo ou Osaka est le bon. Avec une légère corrélation d'information et un peu de GEOINT sur les photos présentes sur LINE ou Twitter, on peut en déduire qu'il se trouve très souvent à Osaka. EN voici un exemple :

![](2/exemple-osaka.png)

Regardons les avis de [Tokyo Three Tides Osaka](https://www.google.com/search?client=firefox-b-d&q=tokyo+three+tides+osaka#lrd=0x6000e70e351eebd3:0x5cfbe83df2d33f5b,1,,,,). En triant par photo les plus récente, on tombe sur un commentaire de Hijikata Takeshi.

![](2/avis.png)

Il contient d'ailleurs une image sur laquelle le flag est écrit.

![](2/flag.png)

### Flag
`BZHCTF{t4tt00s_4r3_p4rt_0f_th3_tr4d1t10n}`

---

## Yakuza (3/5) - Onigiri

### Enoncé

![](gifs/squirtle-eating.gif)

```
Voilà ma preuve ! Les tatouages sont une tradition chez les yakuzas. D’ailleurs il revendique haut et fort qu’il appartient à ce groupe et que c’était une obligation. Bref, maintenant que j’ai ça il faudrait que je travaille sur sa localisation. Je pense que j’en ai pour un moment, c’est jamais chose facile.

Par où je pourrai bien commencer ? Il faut que je garde la tête froide et que je regroupe ce que je possède déjà sur lui. Peut-être que je pourrai retourner sur son groupe LINE ou sur son compte Twitter chercher des informations ? Il a forcément dû parler d’une rencontre avec quelqu’un. Ce serait un bon moyen de pivot. Peut-être que cette personne me donnera plus d’informations.
```

### Détails du challenge

| Event          |  Serie  | Challenge     | Category | Points | Solves |
|----------------|---------|---------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Onigiri (3/5) | OSINT    | ???    | ???    |

### TL;DR
1. Utiliser Shazam (ou autre) pour reconnaitre la chanson et l'artiste => *Onigiri* par *Tonikaku Jay*
2. L'artiste possède un Instagram ([@tonikakujay](https://www.instagram.com/tonikakujay/)) sur lequel il ne semble pas très actif. En regardant ses followers, on remarque son compte personnel ([@jaylaalynvicks](https://www.instagram.com/jaylaalynvicks/))
3. Pivot sur son second compte Instagram sur lequel il est TRES actif.
4. En story, il parle de son ami, aussi connu sous le nom de *Hijikata Takeshi* qui se trouve être notre cible => présence d'un flag en dernière story.
5. [BACKUP] Une autre manière est de parcourir ses storys à la une. Celle ayant pour nom "🚩" contient également le flag.   

### Objectif
L'objectif de ce troisième challenge est de retrouver l'individu. Dans cette traque en 3 étapes, il faut tout d'abord s'attarder sur l'entourage de la cible afin de voir s'il apparaît sur les posts ou storys de potentiels amis à lui. En l'occurence oui, dans la story d'un bon ami rappeur à lui... 

### Méthodologie

Sur le groupe LINE, on remarque que la cible a posté une vidéo :

![](3/video-tonikaku.png)

Elle contient un enregistrement avec un téléphone d'une chanson visiblement américano-japonaise. Deux émoticones sont sur la vidéo, dont un représentant un **onigiri** (petit indice). De plus, il semblerait d'après la description et les commentaires que ce soit la musique d'un bon ami à lui. 

En utilisant Shazam pour retrouver la musique, on tombe sur *"Onigiri"* de l'artiste *Tonikaku Jay*. C'est donc cette personne qui ferait parti de l'entourage de notre cible. 

Avec de très simples recherches, on tombe rapidement sur les réseaux sociaux du rappeur, dont son instagram. 

![](3/tonikakyjay.png)

Cependant, il n'y est pas très actif. Il l'est certainement plus sur son compte personnel, comme l'indique notre cible sur le groupe LINE. 

![](3/comment.png)

*"Ce que je trouve toujours étrange chez lui, c'est qu'il est toujours beaucoup plus actif sur son compte secondaire..."*


En cherchant dans ses followers et en filtrant avec "*Jay*" (déduction à partir de Tonikaku Jay signifiant "*anyway, Jay*"), on tombe sur le compte *@jaylaalynvicks* qui se trouve être son compte principal. 

![](3/jaylaalynvicks.png)

On remarque que le compte possède une story. Dans l'une d'elle, il parle effectivement de son ami et nous donne le flag permettant de valider cette troisième étape du challenge.

![](3/flag.png)

### Flag
`BZHCTF{g0_l1st3n_t0_t0n1k4ku_j4y!}`

---

## Yakuza (4/5) - IS THAT A SUPRA ???

### Enoncé

![](gifs/supra-toyota.gif)

```
Yes, une preuve supplémentaire ! J’ai réussi à faire le lien entre notre suspect et un ami rappeur à lui. D’après ses dires, il serait en route pour une nouvelle destination afin de rejoindre une “connaissance”.

J’ai de la chance qu’il soit assez bavard sur son groupe d’amis, il vient visiblement de me laisser un nouvel indice. Avec ceux déjà présent, je devrais pouvoir être en mesure de connaître sa destination finale.
```

### Détails du challenge

| Event          |  Serie  |          Challenge         | Category | Points | Solves |
|----------------|---------|----------------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | IS THAT A SUPRA ??? (4/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. GEOINT pour trouver sa destination : `Couvent des Jacobins à Rennes` depuis `la gare de Rennes`. 
2. Grâce au screenshot de son fond d'écran, on note qu'il a l'application `Blablacar`
3. Plusieurs posts indiquent sa date de retour et le fait que ce soit un aller-retour avec **le même conducteur**. 
4. Sur l'application Blablacar : recherche d'un trajet le `samedi 18 mars` (fin du BreizhCTF) à 08h00 du *Couvent* à *la gare de Rennes*
5. Ewen poste le trajet => un avis => profil d'Hijikata => avis => flag

### Objectif
L'objectif de ce quatrième challenge reste le même : localiser notre cible. Cette fois-ci, il est possible de la localiser de manière plus précise et de connaître sa destination finale. 

### Méthodologie

Ce challenge difficile se décompose en deux parties : d'une part avec un travail de **GEOINT**. D'autre part avec un travail de **SOCMINT**. 

#### 1. Partie GEOINT

Pour cette première partie, on commence par analyser le poste de Hijikata contenant une photo qui s'apparente être la devanture d'un édifice religieux. On remarque également la présence d'une bannière sur le mur. 

La description est la suivante (traduction approximative) :

`Savez-vous où se trouve la petite photo de la destination ? L'événement est juste à côté`

Il lance le challenge de retrouver le lieu à ses amis, sachant que l'événement auquel il se rend se trouve juste à côté. 

![](4/geoint.png)

En analysant la photo malgré sa qualité, on peut facilement extraire le texte suivant : 

`Marcel Callo 1921 2021`

En faisant une recherche Google du texte, les premiers résultats indiquent que l'événement se passe à Rennes et serait en lien avec le diocèse de cette ville.

![](4/geoint-2.png)

Lorsque l'on s'intéresse de plus près à cet événement, on remarque qu'il a eu lieu en majorité à la `basilique Saint-Aubin`

![](4/geoint-3.png)

La suite logique est donc de rechercher cette basilique sur Google Maps afin de savoir à quoi elle ressemble pour affirmer ou infirmer si la photo y correspond. 

![](4/geoint-4.png)

Avec le bon placement sur Street View, on remarque tout de suite la devanture identique. La bannière y est même toujours accrochée. On a donc la confirmation que l'événement se situe à côté de cette basilique au niveau de `la place Saint-Anne`.

Si le rapprochement n'a pas encore été fait avec le lieu dans lequel vous êtes actuellement (wink wink), une recherche intéressante peut être 

`place saint anne événements rennes`

Les résultats nous remontent rapidement le `Couvent des Jacobins` de Rennes.

![](4/geoint-5.png)

Comme dernière vérification, on peut mesurer la distance entre les deux points pour aperçevoir qu'ils se situent bien juste à côté l'un de l'autre.  


![](4/geoint-6.png)

Cela conclut donc la partie GEOINT. La cible se rend au `Couvent des Jacobins` et sera présente au `BreizhCTF`. 

#### 2. Partie SOCMINT

Maintenant que l'on sait où la cible se rend, nous allons pouvoir utiliser cette information. 

Ici, l'information intéressante est le post dans lequel il parle de sa nouvelle voiture. Il y montre son fond d'écran et nous avons un aperçu de certaines applications qu'il utilise. Parmi celles-ci, on remarque Blablacar. C'est une application pour du covoiturage en Europe. 

`Vous aimez mon fond d'écran ? J'ai acheté une nouvelle voiture`

![](4/bg.png)

De plus, deux autres posts nous indiquent des informations supplémentaires quant à ses déplacements. D'une part, un dans lequel il dit qu'il a hâte de voir comment *ils conduisent* (sous-entendu les étrangers) mais aussi qu'il va faire un aller-retour du lieu de l'événement à la gare. 

`En tant qu'amateur de voitures, j'ai hâte de voir comment ils roulent. Mais le voyage sera court... Ce sera un aller-retour du lieu à la gare`

![](4/post-2.png)

D'autre part, il mentionne dans le second qu'il rentrera à la fin de l'événement le samedi matin. 

`En fait, je rentrerai chez moi dès que l'événement sera terminé. Ce sera samedi matin.`

![](4/post-3.png)

Par ailleurs en commentaire, il dit que ce sera avec le même conducteur. 

`Avec le même conducteur`

![](4/post-4.png)

Grâce à l'ensemble de nos informations, on peut à présent effectuer une recherche sur `Blablacar`. L'essentiel est d'effectuer la recherche sur le trajet retour puisque le trajet aller n'est plus disponible. La recherche en question :

- Depuis : `Le Couvent des Jacobins - Centre des Congrès de Rennes Métropole, Rennes`
- Vers : `Gare de Rennes, Rennes`
- Date : `Samedi 18 mars` (fin du BreizhCTF)

On tombe sur le trajet d'un certain `Ewen`. 

![](4/recherche.png)

Sur le trajet en question, on peut obtenir des informations sur le conducteur. On remarque qu'il a un avis. 

![](4/trajet.png)

![](4/trajet-2.png)

Cet avis a été laissé par Hijikata. C'est un point de pivot pour se diriger sur son compte Blablacar. 

![](4/avis-1.png)

En répétant la même procédure et en se rendant sur les avis que possède Hijikata, on trouve finalement le flag. 

![](4/flag.png)

### Flag
`BZHCTF{w3ll_n0t_4_supr4_just_4_c4rp00l1ng}`

---

## Yakuza (5/5) - Détective Conan

### Enoncé

![](gifs/detective-conan-case-closed.gif)

```
Quelle coïncidence ! Il se trouve que notre suspect était en route pour Rennes. D’après ses messages, il devrait y retrouver un autre membre de son groupe qui participerait lui aussi au BreizhCTF !

D’après les images des caméras de surveillances, il se serait débarrassé de deux téléphones dans deux corbeilles en arrivant au Couvent des Jacobins. Je suis certain qu’il doit bien y avoir des indices sur ceux-ci…
```

### Détails du challenge

| Event          |  Serie  |        Challenge       | Category | Points | Solves |
|----------------|---------|------------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Détective Conan (5/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. Trouver l'emplacement des deux corbeilles 
2. Dans chacune des corbeilles, il y a un téléphone.
3. Sur le téléphone n°1 => boîte de récéption => conversation contenant la première partie du flag
4. Sur le téléphone n°2 => fichiers => photo contenant la seconde partie du flag

### Objectif
L'objectif de ce dernier challenge est de retrouver les téléphones appartenant à l'attaquant. 

### Méthodologie

La première étape consiste à trouver l'emplacement des deux corbeilles. Pour ce faire, aucune technique particulière. Il faut se déplacer et chercher dans le Couvent des Jacobins.

Voici l'emplacement des deux corbeilles :

**Etage 0** : ![](5/emplacement-1.jpg)

**Etage 2** : ![](5/emplacement-2.jpg)

Chacune d'entre elles contient un téléphone. 

En se balandant sur le téléphone n°1 on retrouve plusieurs preuves, notamment une conversation vers un certain "GCC". Cette première conversation contient la première partie du flag. 

![](5/flag-1.jpg)

`BZHCTF{I_h0p3_y0u_l1k3d_`

En fouillant sur le téléphone n°2, on retrouve dans les fichiers du téléphone une photo contenant la seconde partie du flag.

![](5/flag-2.jpg)

`th3_y4kuz4_4dv3ntur3}`

Ce dernier challenge clôt la série "*Yakuza*". J'aimerai beaucoup avoir vos retours sur cette série de challenge, qu'il soit positif ou négatif. Donc n'hésitez pas à me contacter sur Discord ou Twitter. (:

### Flag
`BZHCTF{I_h0p3_y0u_l1k3d_th3_y4kuz4_4dv3ntur3}`

---

## Conclusion

J’espère que cette série de challenges vous a plu. C’était la première fois que je me retrouvais du côté des challenges makers. De ce fait, je suis certain qu’il reste encore beaucoup de choses à améliorer pour que ces challenges soient parfait. Cependant, j’espère vous avoir fait voyager comme j’ai pu le faire cet été lors de mon voyage au Japon. Ces challenges sont intimement liés à mon voyage (tatouage, rencontre du rappeur, le café HIPPO…).

De ce fait, j’aimerai beaucoup avoir vos retours sur cette série de challenge, qu’ils soient positif ou négatif. Ce que vous avez aimé, ou pas. N’hésitez pas à me contacter sur Discord ou Twitter. (:

いってらっしゃい 👋 ! (^^)