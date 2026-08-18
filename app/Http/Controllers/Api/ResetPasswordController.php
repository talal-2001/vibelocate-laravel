<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Throwable;

class ResetPasswordController extends Controller
{
    public function __invoke(Request $request)
    {
        $token = trim((string) $request->input('token', ''));
        $newPassword = (string) $request->input('new_password', '');
        if ($token === '') return $this->error('Reset token is required', 422);
        if (strlen($newPassword) < 8) return $this->error('Password must be at least 8 characters', 422);

        $record = DB::table('password_resets')->where('token', $token)->where('expires_at', '>', now())->select('email')->first();
        if (!$record) return $this->error('Invalid or expired reset token', 400);

        DB::beginTransaction();
        try {
            DB::table('users')->where('email', $record->email)->update(['password_hash' => Hash::make($newPassword)]);
            DB::table('password_resets')->where('email', $record->email)->delete();
            DB::table('refresh_tokens as rt')
                ->join('users as u', 'u.id', '=', 'rt.user_id')
                ->where('u.email', $record->email)
                ->update(['rt.is_revoked' => 1]);
            DB::commit();
            return response()->json(['success' => true, 'message' => 'Password reset successfully']);
        } catch (Throwable) {
            DB::rollBack();
            return $this->error('Password reset failed', 500);
        }
    }

    private function error(string $message, int $status)
    {
        return response()->json(['success' => false, 'message' => $message], $status);
    }
}
