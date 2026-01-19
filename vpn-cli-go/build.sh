set -e
# remove existing mysingbox artifacts
rm -f ../app/libs/mysingbox.aar
rm -f ../app/libs/mysingbox.jar
gomobile bind -target=android -androidapi 21 -o ../app/libs/mysingbox.aar .