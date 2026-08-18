<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Throwable;

class ChangePasswordController extends Controller
{
    public function __invoke(Request $request)
    {
        $user = $request->attributes->get('auth_user');
        $currentPassword = (string) $request->input('current_password', '');
        $newPassword = (string) $request->input('new_password', '');

        if ($currentPassword === '' || $newPassword === '') return $this->error('Current and new passwords are required', 422);
        if (strlen($newPassword) < 8) return $this->error('Password must be at least 8 characters', 422);

        $currentUser = DB::table('users')->where('id', $user['id'])->select('password_hash')->first();
        if (!$currentUser || !Hash::check($currentPassword, $currentUser->password_hash)) {
            return $this->error('Current password is incorrect', 401);
        }

        DB::beginTransaction();
        try {
            DB::table('users')->where('id', $user['id'])->update(['password_hash' => Hash::make($newPassword)]);
            DB::table('refresh_tokens')->where('user_id', $user['id'])->update(['is_revoked' => 1]);
            DB::commit();
            return response()->json(['success' => true, 'message' => 'Password changed. Please log in again.']);
        } catch (Throwable) {
            DB::rollBack();
            return $this->error('Could not change password', 500);
        }
    }

    private function error(string $message, int $status)
    {
        return response()->json(['success' => false, 'message' => $message], $status);
    }
}
