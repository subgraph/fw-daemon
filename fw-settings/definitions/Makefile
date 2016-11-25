generate:
	ruby ./generate.rb

touch:
	ls *.ui | xargs -n1 touch

doctor: touch generate
	git diff --exit-code .
