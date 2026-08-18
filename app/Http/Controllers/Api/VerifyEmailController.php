<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Throwable;

class VerifyEmailController extends Controller
{
    public function __invoke(Request $request)
    {
        $token = trim((string) ($request->isMethod('get') ? $request->query('token', '') : $request->input('token', '')));
        if ($token === '') return $this->error('Verification token is required', 422);

        $verification = DB::table('email_verifications')
            ->where('token', $token)
            ->where('expires_at', '>', now())
            ->select('user_id')
            ->first();
        if (!$verification) return $this->error('Invalid or expired verification token', 400);

        DB::beginTransaction();
        try {
            DB::table('users')->where('id', $verification->user_id)->update([
                'email_verified_at' => now(),
                'status' => 'active',
            ]);
            DB::table('email_verifications')->where('user_id', $verification->user_id)->delete();
            DB::commit();
            return response()->json(['success' => true, 'message' => 'Email verified successfully']);
        } catch (Throwable) {
            DB::rollBack();
            return $this->error('Email verification failed', 500);
        }
    }

    private function error(string $message, int $status)
    {
        return response()->json(['success' => false, 'message' => $message], $status);
    }
}
