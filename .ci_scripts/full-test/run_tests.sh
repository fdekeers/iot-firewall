EXITCODE=0

for file in $GITHUB_WORKSPACE/bin/test/*
do
    if [[ $# -eq 1 && $1 == valgrind ]]
    then
        valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --error-exitcode=1 "$file"
    else
        "$file"
    fi
    # If the exit code is not 0, set EXITCODE to 1
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
done

exit $EXITCODE
