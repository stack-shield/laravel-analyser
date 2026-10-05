<?php

namespace StackShield\Analyser\Checks;

/**
 * Marks a check whose findings are heuristic: shown to the maintainer, but not
 * counted toward the grade. Static analysis cannot see middleware applied
 * elsewhere, policies resolved at runtime, or validation done in a form
 * request, so these checks point at code worth a look rather than proving a
 * vulnerability.
 */
interface Advisory {}
