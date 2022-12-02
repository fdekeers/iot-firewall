# Retrieve this script's path
# (from https://stackoverflow.com/questions/4774054/reliable-way-for-a-bash-script-to-get-the-full-path-to-itself)
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Create dummy interface
sudo $SCRIPTPATH/test/create_interface.sh

# Iterate on all devices
for DEVICE in $SCRIPTPATH/devices/*
do
    if [[ -d $DEVICE ]]
    then
        sudo python3 $SCRIPTPATH/src/translator/translator.py $DEVICE/profile.yaml
    fi
done
