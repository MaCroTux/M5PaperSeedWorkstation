#include <unity.h>
#include "lang.hpp"

void setUp(void) { lang::set(lang::Lang::EN); }

void tearDown(void) { lang::set(lang::Lang::EN); }

void test_tr_english(void) {
  lang::set(lang::Lang::EN);
  TEST_ASSERT_EQUAL_STRING("Seed workstation", lang::tr("SEED WORKSTATION"));
  TEST_ASSERT_EQUAL_STRING("Back", lang::tr("VOLVER"));
}

void test_tr_spanish(void) {
  lang::set(lang::Lang::ES);
  TEST_ASSERT_EQUAL_STRING("SEED WORKSTATION", lang::tr("SEED WORKSTATION"));
  TEST_ASSERT_EQUAL_STRING("VOLVER", lang::tr("VOLVER"));
}

void test_current(void) {
  TEST_ASSERT_EQUAL(lang::Lang::EN, lang::current());
  lang::set(lang::Lang::ES);
  TEST_ASSERT_EQUAL(lang::Lang::ES, lang::current());
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_tr_english);
  RUN_TEST(test_tr_spanish);
  RUN_TEST(test_current);
  return UNITY_END();
}
