for DEVICE in $GITHUB_WORKSPACE/devices/*
do
    sudo python3 $GITHUB_WORKSPACE/src/translator/translator.py $DEVICE/profile.yaml
done
