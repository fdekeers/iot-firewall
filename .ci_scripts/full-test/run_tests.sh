EXITCODE=0

for file in $GITHUB_WORKSPACE/bin/test/*
do
    if [[ $1 && $1 -eq valgrind ]]
    then
        valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --error-exitcode=1 "$file"
    else
        "$file"
    fi
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
done

exit $EXITCODE
