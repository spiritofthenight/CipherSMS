package org.ciphersms.app.crypto;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

/** Phone number canonicalization shared by setup, contact matching, and key derivation. */
public final class PhoneNumbers {
    private static final PhoneNumberUtil UTIL = PhoneNumberUtil.getInstance();
    private PhoneNumbers() { }

    /** User-entered setup/contact numbers must include an international +country prefix. */
    public static String normalizeInternational(String input) throws NumberParseException {
        if (input == null || !input.trim().startsWith("+")) {
            throw new NumberParseException(NumberParseException.ErrorType.INVALID_COUNTRY_CODE,
                    "Enter the number in international format, starting with + and country code");
        }
        Phonenumber.PhoneNumber parsed = UTIL.parse(input.trim(), null);
        if (!UTIL.isValidNumber(parsed)) {
            throw new NumberParseException(NumberParseException.ErrorType.NOT_A_NUMBER, "This does not look like a valid phone number");
        }
        return UTIL.format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164);
    }

    /** Incoming sender addresses are not always formatted internationally by every network. */
    public static String normalizeIncoming(String input, String localE164) {
        if (input == null || input.trim().isEmpty()) return null;
        String candidate = input.trim();
        try {
            Phonenumber.PhoneNumber parsed;
            if (candidate.startsWith("+")) {
                parsed = UTIL.parse(candidate, null);
            } else {
                Phonenumber.PhoneNumber local = UTIL.parse(localE164, null);
                String region = UTIL.getRegionCodeForNumber(local);
                if (region == null || region.equals("ZZ")) return null;
                parsed = UTIL.parse(candidate, region);
            }
            if (!UTIL.isPossibleNumber(parsed)) return null;
            return UTIL.format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException ignored) {
            return null;
        }
    }
}
