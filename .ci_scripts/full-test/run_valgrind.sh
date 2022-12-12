for file in $GITHUB_WORKSPACE/bin/test/*
do
    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --error-exitcode=1 "$file"
done
