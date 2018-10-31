# Variable is used in TabExpansion.ps1
$params = @{
    'kerberos::list' = '/export'
}

# Variable is used in GitTabExpansion.ps1
$gitParamValues = @{
    blame = @{
        encoding = 'utf-8 none'
    }
    branch = @{
        color = 'always never auto'
        abbrev = '7 8 9 10'
    }
    checkout = @{
        conflict = 'merge diff3'
    }
    'cherry-pick' = @{
        strategy = 'resolve recursive octopus ours subtree'
    }
    commit = @{
        'cleanup' = 'strip whitespace verbatim scissors default'
    }
    diff = @{
        unified = '0 1 2 3 4 5'
        'diff-algorithm' = 'default patience minimal histogram myers'
        color = 'always never auto'
        'word-diff' = 'color plain porcelain none'
        abbrev = '7 8 9 10'
        'diff-filter' = 'A C D M R T U X B *'
        'inter-hunk-context' = '0 1 2 3 4 5'
        'ignore-submodules' = 'none untracked dirty all'
    }
    difftool = @{
        tool = 'vimdiff vimdiff2 araxis bc3 codecompare deltawalker diffmerge diffuse ecmerge emerge gvimdiff gvimdiff2 kdiff3 kompare meld opendiff p4merge tkdiff xxdiff'
    }
    fetch = @{
        'recurse-submodules' = 'yes on-demand no'
        'recurse-submodules-default' = 'yes on-demand'
    }
    init = @{
        shared = 'false true umask group all world everybody o'
    }
    log = @{
        decorate = 'short full no'
        'no-walk' = 'sorted unsorted'
        pretty = 'oneline short medium full fuller email raw'
        format = 'oneline short medium full fuller email raw'
        encoding = 'UTF-8'
        date = 'relative local default iso rfc short raw'
    }
    merge = @{
        strategy = 'resolve recursive octopus ours subtree'
        log = '1 2 3 4 5 6 7 8 9'
    }
    mergetool = @{
        tool = 'vimdiff vimdiff2 araxis bc3 codecompare deltawalker diffmerge diffuse ecmerge emerge gvimdiff gvimdiff2 kdiff3 kompare meld opendiff p4merge tkdiff xxdiff'
    }
    notes = @{
        strategy = 'manual ours theirs union cat_sort_uniq'
    }
    pull = @{
        strategy = 'resolve recursive octopus ours subtree'
        'recurse-submodules' = 'yes on-demand no'
        'no-recurse-submodules' = 'yes on-demand no'
        rebase = 'false true preserve'
    }
    push = @{
        'recurse-submodules' = 'check on-demand'
    }
    rebase = @{
        strategy = 'resolve recursive octopus ours subtree'
    }
    revert = @{
        strategy = 'resolve recursive octopus ours subtree'
    }
    show = @{
        pretty = 'oneline short medium full fuller email raw'
        format = 'oneline short medium full fuller email raw'
        encoding = 'utf-8'
    }
    status = @{
        'untracked-files' = 'no normal all'
        'ignore-submodules' = 'none untracked dirty all'
    }
}
