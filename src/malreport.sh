TYPE=`file "$1" | cut -f 2 -d ':'`
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo Filename: $1
echo Magic Type: $TYPE
SHA2SUM=`sha256sum "$1" | cut -f 1 -d ' '`
echo sha256:$SHA2SUM
echo sha1: `sha1sum "$1" | cut -f 1 -d ' '`
echo md5: `md5sum "$1" | cut -f 1 -d ' '`

echo
echo "============="
echo "- EXIF Data -"
echo "============="
exiftool "$1"

echo
echo "======================"
echo "- Virus Total Report -"
echo "======================"
if [ -z $VT_API_KEY ]; then
  echo "ERROR: please set VT_API_KEY in bashrc."
else
  curl --request POST \
    --url 'https://www.virustotal.com/vtapi/v2/file/report' \
    -d apikey=${VT_API_KEY} \
    -d resource=${SHA2SUM} | python -m json.tool
fi

if [[ $TYPE == *"PE"* ]]; then
  echo
  echo "==========="
  echo "- PE INFO -"
  echo "==========="
  readpe "$1"

fi

