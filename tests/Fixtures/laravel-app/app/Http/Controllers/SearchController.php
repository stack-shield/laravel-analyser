<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SearchController
{
    public function search(Request $request)
    {
        // Vulnerable: raw SQL with tainted input
        $results = DB::selectRaw("SELECT * FROM posts WHERE title LIKE '%" . $request->input('q') . "%'");

        return $results;
    }

    public function safe(Request $request)
    {
        // Safe: uses parameter binding
        $results = DB::selectRaw("SELECT * FROM posts WHERE title LIKE ?", ['%' . $request->input('q') . '%']);

        return $results;
    }

    public function dangerous(Request $request)
    {
        // Vulnerable: eval with user input
        eval($request->input('code'));

        // Vulnerable: shell_exec with user input
        shell_exec('ls ' . $request->input('path'));
    }
}
