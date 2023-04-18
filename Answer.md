### Maha Gharras 
# TD-ransomware 
## Chiffrement

### Q1.
L'algorithme utilisé est le cryptage XOR. Il n'est pas considéré comme robuste, car en ayant accès à une version chiffrée et non chiffrée d'un même fichier, il est possible de retrouver la clé utilisée pour le chiffrement.

### Q2.
Hacher le sel et la clé directement n'est pas recommandé car cela n'apporte pas de réelle amélioration de la sécurité. Les sel et clé sont déjà des valeurs aléatoires et uniques, et les hacher ne les rendrait pas plus difficiles à deviner. Utiliser un HMAC est plutôt utilisé pour garantir l'intégrité et l'authenticité d'un message, ce qui n'est pas l'objectif principal dans ce contexte de chiffrement de fichiers.

## Setup
### Q3.
Vérifier la présence d'un fichier token.bin existant permet d'éviter d'écraser les données de chiffrement précédentes, ce qui pourrait empêcher le déchiffrement des fichiers déjà chiffrés et causer une perte irréversible d'informations.

## Vérifier et utiliser la clef

### Q4.
Pour vérifier que la clé est correcte, on compare le token dérivé à partir du sel et de la clé candidate avec le token original stocké.






