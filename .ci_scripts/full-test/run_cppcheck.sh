EXITCODE=0

# Pattern matching on all source files
for file in $(find $GITHUB_WORKSPACE -name *.c)
do
    # Run cppcheck on each file
    cppcheck --error-exitcode=1 "$file"
    # If the exit code is not 0, set EXITCODE to 1
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
done

exit $EXITCODE
