start = 1132
roundn = 1
interest = 0.0125
payment = 25
maxround = 70

while roundn != maxround:
  remain = round(start - payment, 2)
  interest_rate = round(remain * interest, 2)
  print(f"Round: {roundn} | Balance: {start} | Monthly Payment: {payment} | Interest: {interest_rate} | Remaining Balance: {remain}")
  start = round(remain + interest_rate, 2)
  
  
  roundn = roundn + 1

