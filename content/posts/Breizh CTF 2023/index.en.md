---
title: '[BreizhCTF 2023] - Yakuza Serie'
date: 2023-03-19T22:00:53+01:00
lastmod: 2023-03-19T22:00:53+01:00
draft: false
authors: ["hashp4"]
description: "Solution to the OSINT challenges I created for BreizhCTF 2023."
summary: "Solution to the OSINT challenges I created for BreizhCTF 2023."
featuredImage: "feature.png"

tags: ["OSINT", "BreizhCTF", "SOCMINT", "GEOINT", "irl"]
hiddenFromHomePage: true

categories: ["Writeup"]
---

## Introduction

During BreizhCTF 2023, which took place from 17/03/2023 to 18/03/2023, I had the opportunity to carry out some of the OSINT challenges. As a CTF player myself and a great fan of OSINT, my idea was to create a series of realistic challenges, something rarely seen in CTF. The aim was to immerse the player in a real investigation. The player quickly finds himself overwhelmed by a flow of information, and it's up to him to sort it all out, in conjunction with the guiding statement. Several essential components were required to create these challenges:

- the theme and associated language (Japanese),
- the use of real actors,
- the use of real accounts.

The series comprises 5 challenges combining several OSINT techniques: SOCMINT, GEOINT and physical investigation. The aim is to find and trace an attacker, a member of a Japanese criminal group whose objective is to meet a contact of his in France during the BreizhCTF. Throughout these challenges, the player is required to collect various pieces of evidence that will be useful in incriminating the man in question.

---

## Yakuza (1/5) - Nihon he yōkoso

### Challenge description 

![](gifs/cat-bowl.gif)

```
Oh tiens, je viens de recevoir un message. À cette heure-là ? Sur mon tél pro ? C’est étrange. Il faut que je l’ouvre sans plus tarder. Moi qui pensais pouvoir me détendre au BreizhCTF avec une bonne galette saucisse, me voilà de nouveau sur une enquête…

“Good evening Conan,

I hope your stay in Rennes is going well. Unfortunately, we have to interrupt it. We're asking for your help tonight, as part of our YKZ_001 investigation. As you know, several months ago we were tracking down a group of yakuzas who had compromised an OIV for profit. However, they have left almost no trace since then.

It was only a few minutes ago that we intercepted a message from the group about their next attack. Luckily, it contained a signature. It consists of a series of characters in Japanese: "土方剛史".

We're sure that with this information, you'll be able to track down one of the players in this group.

We're counting on your expertise to carry out this investigation. Remember, every detail counts. Gathering, recording and cross-checking information is essential to the success of any mission. You only have a few hours to find the individual and help uncover their next target.

Good luck to you.”
```

### Challenge details

| Event          | Serie  |       Challenge     | Category | Points | Solves |
|----------------|--------|---------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza |Nihon he yōkoso (1/5)| OSINT    | N/C        | N/C    |

### TL;DR
1. Translation of signature into rōmaji: `土方剛史` => *Takeshi Hijikata*
2. Twitter name search -> Account [@HijikataTakeshi](https://twitter.com/HijikataTakeshi/)
3. In a tweet, the target talks about a group in which he would be more active. He is said to be on a very popular social network in Japan.
4. Search for popular Japanese social networks => **LINE** is #1
5. Search for a user on LINE with the same username as on Twitter (also works with first name + last name) => We find his account
6. In the banner, there's a URL to join a LINE group
7. When you join, the flag appears in the "Notes" section of the group.

### Goal
The aim of this first challenge is to link the message signature to a real person. This means finding traces of the target on the Internet.

### Methodology
To do this, we need to start with this famous signature: `土方剛史`. Unless you have the JLPT and understand its meaning directly, you need to start by translating it. To do this, we can use **DeepL**.

![](1/traduction-signature.png)

So we end up with a first and last name: `Takeshi Hijikata.` By searching for him on Twitter, we can find his account.

![](1/compte-twitter.png)

After investigating his account, two tweets turned out to be particularly interesting:

![](1/tweet-1.png)
![](1/tweet-2.png)

The target itself tells us that it happens to be more active on another social network. This one is said to be the most popular in Japan. After a rather basic internet search, we quickly come across `LINE`.

![](1/popular-sn.png)

Searching for the user's name on LINE brings up his account:

![](1/compte-line.png)

We notice a link in the banner of his account. This allows you to join your LINE group. Note that to join a group, you need the mobile application.

![](1/compte-line-2.png)

Once we're on the group, we head for the notes, which contain a wealth of information, including our flag, which marks the end of this first challenge.

![](1/flag.png)

### Flag

`BZHCTF{L1N3_1s_v3ry_f4m0us_1n_J4p4n}`

---

## Yakuza (2/5) - Tebori

### Challenge description

![](gifs/swag-cat-swagger.gif)

```
Perfect, I managed to find the individual in question and join his group of friends. To say the least, it's a real goldmine in terms of information. However, there's nothing to link him to this group of yakuza... But there's one note that catches my eye. In it, he mentions a tattoo store and "Kamon Tomoe".

I feel there's something to be dug up here.

In any case, I've got to keep going before he notices something. He seems very active on this newsgroup.
```

### Challenge details

| Event          |  Serie  | Challenge     | Category | Points | Solves |
|----------------|---------|---------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Tebori (2/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. Note on a tattoo store + photo of a `Kamon Tomoe`.
2. Search "most famous tattoo shop in japan" => Tokyo Three Tides Tattoo
3. Store logo is a `Kamon Tomoe` => store confirmation
4. There are 2 in Japan (Osaka and Tokyo). Thanks to the photos on the LINE group, we know it's in Osaka. 
5. Filter by most recent comment to obtain the flag.

### Goal
The aim of this second challenge is now to link the target to the Yakuza group. Proof of membership must be obtained. 

### Methodology

As the statement for this second challenge underlines, there are two messages on the LINE group about a tattoo parlour and tattooing itself. In these, our target says she would have had a traditional tattoo in a store with a *"Kamon Tomoe "* sign.

![](2/post-line.png)

The tattoo in question:

![](2/post-line-2.png)

The first step is to research tattoo stores in Japan. A good place to start is with the best-known stores. 

![](2/famous-tattoo-shop.png)

We quickly, if not immediately, come across "Tokyo Three Tides". Researching this sign, we come across the store's logo:

![](2/logo-tattoo.png)

The logo turns out to be a kind of *Kamon Tomoe*, telling us we're on the right track. Considering that the target had a tattoo there, he potentially left a review or photo. It remains to be seen which of the two stores in Tokyo or Osaka is the right one. With a slight correlation of information and a little GEOINT on the photos present on LINE or Twitter, we can deduce that he is very often in Osaka. Here's an example:

![](2/exemple-osaka.png)

Let's talk a look at the reviews of [Tokyo Three Tides Osaka](https://www.google.com/search?client=firefox-b-d&q=tokyo+three+tides+osaka#lrd=0x6000e70e351eebd3:0x5cfbe83df2d33f5b,1,,,,). Sorting by most recent photo, we come across a comment by Hijikata Takeshi.

![](2/avis.png)

It also contains an image on which the flag is written.

![](2/flag.png)

### Flag
`BZHCTF{t4tt00s_4r3_p4rt_0f_th3_tr4d1t10n}`

---

## Yakuza (3/5) - Onigiri

### Challenge description

![](gifs/squirtle-eating.gif)

```
Here's my proof! Tattoos are a yakuza tradition. In fact, he claims loud and clear that he belongs to this group and that it was an obligation. Anyway, now that I've got that, I'll have to work on locating it. I think I'll be a while, it's never easy.

Where should I start? I need to keep a cool head and pull together what I've already got on him. Maybe I could go back to his LINE group or his Twitter account and look for information? He's bound to have mentioned meeting someone. That would be a good pivot point. Maybe that person will give me more information.
```

### Challenge details

| Event          |  Serie  | Challenge     | Category | Points | Solves |
|----------------|---------|---------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Onigiri (3/5) | OSINT    | ???    | ???    |

### TL;DR
1. Use Shazam (or other) to recognize the song and artist => *Onigiri* by *Tonikaku Jay*.
2. The artist has an Instagram ([@tonikakujay](https://www.instagram.com/tonikakujay/)) on which he doesn't seem very active. Looking at his followers, we notice his personal account ([@jaylaalynvicks](https://www.instagram.com/jaylaalynvicks/))
3. Pivot to his second Instagram account on which he is VERY active.
4. In story, he talks about his friend, also known as *Hijikata Takeshi* who happens to be our target => presence of a flag in last story.
5. [BACKUP] Another way is to browse through his front-page stories. The one with the name "🚩" also contains the flag. 

### Objectif
The aim of this third challenge is to find the individual. In this 3-stage hunt, the first step is to look at the target's entourage to see if he appears on the posts or stories of potential friends of his. In this case, yes, in the story of a good rapper friend of his...

### Méthodologie

On the LINE group, we notice that the target has posted a video:

![](3/video-tonikaku.png)

It contains a telephone recording of an obviously Japanese-American song. The video features two emoticons, one of which represents an **onigiri** (hint hint). What's more, it seems from the description and comments that this is the music of a good friend of his. 

Using Shazam to find the music, we come across *"Onigiri "* by artist *Tonikaku Jay*. So this is the person who would be part of our target's entourage. 

With a few simple searches, we quickly came across the rapper's social networks, including his instagram.

![](3/tonikakyjay.png)

However, he's not very active there. He's certainly more active on his personal account, as our target on the LINE group shows. 

![](3/comment.png)

*"What I always find strange about him is that he's always much more active on his secondary account..."*


Searching his followers and filtering with "*Jay*" (deduced from Tonikaku Jay meaning "*anyway, Jay*"), we come across the account *@jaylaalynvicks* which happens to be his main account.

![](3/jaylaalynvicks.png)

We notice that the account has a story. In one of them, he talks about his friend and gives us the flag to validate the third stage of the challenge.

![](3/flag.png)

### Flag
`BZHCTF{g0_l1st3n_t0_t0n1k4ku_j4y!}`

---

## Yakuza (4/5) - IS THAT A SUPRA ???

### Challenge description

![](gifs/supra-toyota.gif)

```
Yes, more proof! I managed to make the connection between our suspect and a rapper friend of his. According to him, he's on his way to a new destination to meet up with an "acquaintance".

I'm lucky that he's quite talkative about his group of friends, he's obviously just left me a new clue. With those already present, I should be able to find out his final destination.
```

### Détails du challenge

| Event          |  Serie  |          Challenge         | Category | Points | Solves |
|----------------|---------|----------------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | IS THAT A SUPRA ??? (4/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. GEOINT to find your destination: `Couvent des Jacobins in Rennes` from `Rennes train station`. 
2. Thanks to the screenshot of his wallpaper, we can see that he has the `Blablacar` application.
3. Several posts indicate his return date and the fact that it's a round trip with **the same driver**. 
4. On the Blablacar app: search for a trip on `Saturday March 18` (end of BreizhCTF) at 08:00 from *Couvent* to *Rennes train station*.
5. Ewen posts the trip => a review => Hijikata's profile => review => flag

### Goal
The aim of this fourth challenge remains the same: to locate our target. This time, it's possible to pinpoint the target's exact location and final destination.

### Methodology

This difficult challenge can be broken down into two parts: on the one hand with **GEOINT** work. On the other, **SOCMINT**.

#### 1. GEOINT Part

For this first part, we begin by analyzing Hijikata's post containing a photo that appears to be the front of a religious building. We also note the presence of a banner on the wall. 

The description reads (roughly translated):

Do you know where the small photo of the destination is? The event is just around the corner.

He challenges his friends to find the location, knowing that the event he's going to is right next door.

![](4/geoint.png)

By analyzing the photo despite its quality, we can easily extract the following text: 

`Marcel Callo 1921 2021`

A Google search of the text yields initial results indicating that the event took place in Rennes, and would be related to the diocese of that city.

![](4/geoint-2.png)

A closer look at this event reveals that most of it took place at the `Basilica of Saint-Aubin`.

![](4/geoint-3.png)

The next logical step is to search for this basilica on Google Maps to find out what it looks like and confirm or deny whether the photo matches.

![](4/geoint-4.png)

With the right placement on Street View, you'll immediately notice the identical storefront. The banner still hangs there. This confirms that the event is taking place right next to this basilica, at 'Place Saint-Anne'.

If you haven't yet made the connection with your current location (wink wink), an interesting search might be 

`place saint anne events rennes`

The results quickly bring up `Couvent des Jacobins` in Rennes.

![](4/geoint-5.png)

As a final check, we can measure the distance between the two points to see if they are right next to each other. 

![](4/geoint-6.png)

This concludes the GEOINT section. The target goes to the `Couvent des Jacobins` and will be present at the `BreizhCTF`.

#### 2. SOCMINT Part

Now that we know where the target is going, we can use this information. 

Here, the interesting information is the post in which he talks about his new car. He shows his wallpaper and we get a glimpse of some of the applications he uses. These include Blablacar. It's an application for carpooling in Europe. 

`Do you like my wallpaper? I bought a new car`

![](4/bg.png)

In addition, two other posts give us further information about his whereabouts. Firstly, one in which he says he can't wait to see how *they drive* (implying foreigners) but also that he'll be making a round trip from the venue to the station. 

`As a car enthusiast, I can't wait to see how they drive. But it's going to be a short trip... It will be a round trip from the venue to the station`

![](4/post-2.png)

On the other hand, he mentions in the second that he'll be going home at the end of the event on Saturday morning. 

`In fact, I'll be going home as soon as the event is over. That will be Saturday morning.

![](4/post-3.png)

Also, as a comment, he says it will be with the same driver. 

`With the same driver`

![](4/post-4.png)

With all our information, we can now carry out a search on `Blablacar`. The most important thing is to search for the return journey, since the outward journey is no longer available. The search in question :

- From: `Le Couvent des Jacobins - Centre des Congrès de Rennes Métropole, Rennes` to: `Rennes train station`.
- To: `Gare de Rennes, Rennes` (Rennes train station)
- Date: `Saturday March 18` (end of BreizhCTF)

We come across the route of a certain `Ewen`.

![](4/recherche.png)

On the route in question, we can obtain information about the driver. You'll notice that he has a review.

![](4/trajet.png)

![](4/trajet-2.png)

This review was left by Hijikata. This is a pivotal point for navigating to your Blablacar account.

![](4/avis-1.png)

Repeating the same procedure and going to Hijikata's reviews, we finally find the flag.

![](4/flag.png)

### Flag
`BZHCTF{w3ll_n0t_4_supr4_just_4_c4rp00l1ng}`

---

## Yakuza (5/5) - Détective Conan

### Challenge description

![](gifs/detective-conan-case-closed.gif)

```
What a coincidence! Our suspect happened to be on his way to Rennes. According to his messages, he was meeting another member of his group who was also taking part in the BreizhCTF!

According to CCTV footage, he disposed of two phones in two baskets when he arrived at the Couvent des Jacobins. I'm sure there must be some clues on them...
```

### Challenge details

| Event          |  Serie  |        Challenge       | Category | Points | Solves |
|----------------|---------|------------------------|----------|--------|--------|
| BreizhCTF 2023 | Yakuza  | Détective Conan (5/5)  | OSINT    | N/C    | N/C    |

### TL;DR
1. Find the location of the two baskets 
2. There is a telephone in each of the garbage cans.
3. On phone n°1 => inbox => conversation containing the first part of the flag
4. On phone n°2 => files => photo containing the second part of the flag

### Goal
The aim of this latest challenge is to find the phones belonging to the attacker.

### Methodology

The first step is to find the location for the two baskets. No special technique is required. Just move around and look for them in the Jacobins Convent.

Here are the locations of the two baskets:

**Etage 0** : ![](5/emplacement-1.jpg)

**Etage 2** : ![](5/emplacement-2.jpg)

Each contains a telephone. 

Browsing through phone n°1, we find several pieces of evidence, including a conversation with a certain "GCC". This first conversation contains the first part of the flag.

![](5/flag-1.jpg)

`BZHCTF{I_h0p3_y0u_l1k3d_`

Rummaging around on phone no. 2, we find a photo in the phone's files containing the second part of the flag.

![](5/flag-2.jpg)

`th3_y4kuz4_4dv3ntur3}`

This final challenge brings the "*Yakuza*" series to a close. I'd love to hear your feedback on this challenge series, whether positive or negative. So don't hesitate to contact me on Discord or Twitter. (:

### Flag
`BZHCTF{I_h0p3_y0u_l1k3d_th3_y4kuz4_4dv3ntur3}`

---

## Conclusion

I hope you enjoyed this series of challenges. This was my first time on the makers' side. As such, I'm sure there's still a lot of room for improvement to make these challenges perfect. However, I hope to have taken you on a journey, as I did this summer on my trip to Japan. These challenges are closely linked to my trip (tattooing, meeting the rapper, the HIPPO café...).

So I'd love to hear your feedback on this series of challenges, whether positive or negative. What you liked or didn't like. Don't hesitate to contact me on Discord or Twitter. (:

いってらっしゃい 👋 ! (^^)