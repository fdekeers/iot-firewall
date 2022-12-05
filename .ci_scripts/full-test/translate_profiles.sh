for DEVICE in $GITHUB_WORKSPACE/devices/*
do
    if [[ -d $DEVICE ]]
    then
        python3 $GITHUB_WORKSPACE/src/translator/translator.py $DEVICE/profile.yaml
    fi
done
