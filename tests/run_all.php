<?php
// Runs every *_test.php in this directory as its own PHP CLI process (each
// test spawns its own server subprocess, so tests must not share ports/state)
// and reports a combined pass/fail. See tests/README.md.
$dir = __DIR__;
$tests = glob("$dir/*_test.php");
sort($tests);

if (empty($tests)) {
    fwrite(STDERR, "no *_test.php files found in $dir\n");
    exit(1);
}

$failed = [];
foreach ($tests as $test) {
    $name = basename($test);
    echo str_repeat('=', 70) . "\n";
    echo "Running $name\n";
    echo str_repeat('=', 70) . "\n";
    $cmd = [PHP_BINARY, $test];
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
    fclose($pipes[0]);
    $code = proc_close($proc);
    if ($code !== 0) {
        $failed[] = $name;
    }
    echo "\n";
}

echo str_repeat('=', 70) . "\n";
if (empty($failed)) {
    printf("ALL %d TEST FILES PASSED\n", count($tests));
    exit(0);
}

printf("%d/%d TEST FILES FAILED: %s\n", count($failed), count($tests), implode(', ', $failed));
exit(1);
