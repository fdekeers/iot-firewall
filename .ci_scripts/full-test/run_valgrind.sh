for file in $GITHUB_WORKSPACE/bin/test/*
do
    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all "$file"
done
